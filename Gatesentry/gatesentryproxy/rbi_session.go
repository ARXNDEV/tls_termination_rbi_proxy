package gatesentryproxy

// Per-session RBI: every isolated navigation launches a FRESH throwaway container
// (a complete Chromium, kiosk-locked to the one URL) published on its own host
// port, and the client opens that session's stream in a NEW window. Idle sessions
// are reaped. This replaces the old single shared `docker exec rbi-open` flow.

import (
	"context"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rbiSession struct {
	id, name, url    string
	tcpPort, udpPort int
	created          time.Time
	lastActive       time.Time
}

var (
	rbiMu             sync.Mutex
	rbiSessionsByHost = map[string]*rbiSession{}
	rbiGCOnce         sync.Once
	rbiSeq            int

	// per-host launch serialization: prevents the browser's concurrent
	// document/asset/WS requests from each spawning a duplicate container for the
	// same host (which would split the session and break WebRTC signaling).
	rbiLaunchMu   = map[string]*sync.Mutex{}
	rbiLaunchMuMu sync.Mutex
)

func rbiHostLaunchLock(host string) *sync.Mutex {
	rbiLaunchMuMu.Lock()
	defer rbiLaunchMuMu.Unlock()
	lm, ok := rbiLaunchMu[host]
	if !ok {
		lm = &sync.Mutex{}
		rbiLaunchMu[host] = lm
	}
	return lm
}

// rbiHostOf returns the lowercased host (no port) for a raw URL/host string.
func rbiHostOf(raw string) string {
	if pu, err := neturl.Parse(raw); err == nil && pu.Host != "" {
		return strings.ToLower(pu.Hostname())
	}
	h := raw
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:?#"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// rbiKioskURL is the URL the throwaway container's kiosk Chromium opens. We
// normalize to the host ROOT (scheme://host/) so the stream always lands on the
// site's homepage — never on whatever sub-resource (e.g. an async XHR like
// www.google.com/async/folae) happened to win the host-keyed launch race.
func rbiKioskURL(raw string) string {
	// Frontend override: when set, EVERY isolated session's container opens this URL
	// instead of the requested site. Used to serve a lightweight YouTube frontend
	// (Invidious/Piped) that renders under GPU-less software rendering, while the
	// client's URL bar still shows the requested origin (proxy-forward).
	if f := rbiEnv("RBI_FORCE_KIOSK_URL", ""); f != "" {
		return f
	}
	scheme, host := "https", ""
	if pu, err := neturl.Parse(raw); err == nil && pu.Host != "" {
		if pu.Scheme != "" {
			scheme = pu.Scheme
		}
		host = pu.Host // preserves host:port if present
	}
	if host == "" {
		host = rbiHostOf(raw)
	}
	// (Removed the youtube->m.youtube.com workaround: with Mesa lavapipe software
	// rendering, DESKTOP youtube.com now renders in the no-GPU container, so we open
	// each site at its own root and serve the full desktop experience.)
	hl := strings.ToLower(host)
	if i := strings.LastIndex(hl, ":"); i >= 0 {
		hl = hl[:i]
	}
	// Teams' free-meeting entry lives at /gather (the host root is a login/landing
	// page). Pin teams to /gather unconditionally — like youtube->m.youtube — so the
	// container always opens the meeting page and a sub-resource can't win the
	// host-keyed launch race and set the kiosk to e.g. /gather/keyboard_layouts.json.
	if hl == "teams.live.com" {
		return "https://teams.live.com/gather"
	}
	return scheme + "://" + host + "/"
}

// rbiForwardEndpoint is where the proxy reverse-proxies this session's HTTP/WS to.
func (s *rbiSession) rbiForwardEndpoint() string {
	return "127.0.0.1:" + strconv.Itoa(s.tcpPort)
}

// rbiShouldIsolate reports whether a host should be TLS-bumped + isolated. Only
// the configured target hosts (RBI_ISOLATE_HOSTS, default youtube.com) are
// isolated; everything else (the proxied browser's own telemetry/fonts/googleapis
// background traffic) is tunneled straight through, so we don't spawn a container
// per Google service and starve the real session.
func rbiShouldIsolate(hostport string) bool {
	host := hostport
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, h := range strings.Split(rbiEnv("RBI_ISOLATE_HOSTS", "youtube.com"), ",") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

func rbiEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func rbiImage() string   { return rbiEnv("RBI_IMAGE", "rbi-chrome-neko:latest") }

// rbiDeviceExists reports whether a host device node (e.g. a v4l2loopback /dev/videoN)
// is present, so the webcam --device mount is only added when it can actually succeed.
func rbiDeviceExists(path string) bool { _, err := os.Stat(path); return err == nil }

// rbiVideoPipeline returns the GStreamer pipeline neko uses to encode the screen.
// neko's auto-default is only ~2 Mbps VP8 @25fps, which looks blocky at 1080p. The
// container encodes natively (arm64) with CPU to spare, and media flows over loopback
// (NAT1TO1=127.0.0.1, no bandwidth limit), so we raise bitrate + fps + quality preset
// substantially. Tunable without a rebuild via env:
//   RBI_VIDEO_BITRATE  (bits/s, default 8000000 = 8 Mbps)
//   RBI_VIDEO_FPS      (frames/s, default 30 — also sets the X display refresh)
//   RBI_VIDEO_CPU_USED (vp8 speed/quality, 0=best..16=fastest, default 2)
// Mirrors neko's default pipeline structure (named elements: framerate/encoder/appsink)
// so neko's syntax check passes; only the tunables differ.
func rbiVideoPipeline() string {
	br := rbiEnv("RBI_VIDEO_BITRATE", "8000000")
	fps := rbiEnv("RBI_VIDEO_FPS", "30")
	cpu := rbiEnv("RBI_VIDEO_CPU_USED", "2")
	return "ximagesrc display-name=:99.0 show-pointer=false use-damage=false" +
		" ! capsfilter caps=video/x-raw,framerate=" + fps + "/1 name=framerate" +
		" ! videoconvert ! queue" +
		" ! vp8enc name=encoder target-bitrate=" + br + " end-usage=cbr threads=8 deadline=1" +
		" buffer-size=12288 keyframe-max-dist=30 cpu-used=" + cpu +
		" undershoot=95 buffer-initial-size=6144 buffer-optimal-size=9216" +
		" min-quantizer=2 max-quantizer=20" +
		" ! appsink name=appsink"
}
func rbiIdleTTL() time.Duration {
	if n, err := strconv.Atoi(rbiEnv("RBI_IDLE_SECONDS", "600")); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 10 * time.Minute
}

// rbiLaunchSession returns a running per-session container for rawURL's HOST,
// reusing an existing live one for that host or launching a fresh throwaway.
// Host-keyed so every request to e.g. youtube.com routes to the same container.
func rbiLaunchSession(rawURL string) (*rbiSession, error) {
	host := rbiHostOf(rawURL)
	// Serialize launches for this host so concurrent requests reuse ONE container.
	lm := rbiHostLaunchLock(host)
	lm.Lock()
	defer lm.Unlock()
	rbiMu.Lock()
	if s, ok := rbiSessionsByHost[host]; ok && rbiContainerRunning(s.name) {
		s.lastActive = time.Now()
		rbiMu.Unlock()
		return s, nil
	}
	rbiSeq++
	seq := rbiSeq
	rbiMu.Unlock()

	tcpPort, err := rbiFreeTCPPort()
	if err != nil {
		return nil, fmt.Errorf("alloc tcp port: %w", err)
	}
	udpPort, err := rbiFreeUDPPort()
	if err != nil {
		return nil, fmt.Errorf("alloc udp port: %w", err)
	}
	// TCP mux for WebRTC media as a FALLBACK to UDP. On Docker Desktop for Mac, UDP
	// port-forwarding is unreliable — media times out so the client churns (WS connects,
	// peer never does -> black). TCP forwarding is reliable, so neko also advertises a
	// TCP ICE candidate and the client falls back to it when UDP can't traverse.
	tcpMuxPort, err := rbiFreeTCPPort()
	if err != nil {
		return nil, fmt.Errorf("alloc tcp-mux port: %w", err)
	}
	id := strconv.Itoa(seq) + "-" + strconv.FormatInt(time.Now().UnixNano()%100000, 10)
	name := "rbi-sess-" + id

	args := []string{
		"run", "-d", "--rm", "--name", name,
		"-p", fmt.Sprintf("%d:8080", tcpPort),
		"-p", fmt.Sprintf("%d:%d/udp", udpPort, udpPort),
		"-p", fmt.Sprintf("%d:%d", tcpMuxPort, tcpMuxPort),
		"--cap-add=NET_ADMIN", "--security-opt", "no-new-privileges:true", "--shm-size=1g",
		"-e", "ALLOWED_URL=" + rbiKioskURL(rawURL),
		// DEMO_DIRECT lets the kiosk render on hosts without the :3129 egress
		// listener (e.g. this arm64 Mac). On a production x86 host set
		// RBI_PROXY_DEMO_DIRECT=0 to keep the full Layer-B firewall + egress proxy.
		"-e", "RBI_DEMO_DIRECT=" + rbiEnv("RBI_PROXY_DEMO_DIRECT", "1"),
		"-e", "PROXY_HOST=" + rbiEnv("RBI_PROXY_HOST", "dummy"),
		"-e", "PROXY_PORT=" + rbiEnv("RBI_EGRESS_PORT", "3129"),
		"-e", "TURN_HOST=" + rbiEnv("RBI_TURN_HOST", "dummy"),
		"-e", "TURN_PORT=" + rbiEnv("RBI_TURN_PORT", "3478"),
		"-e", "NEKO_DESKTOP_SCREEN=" + rbiEnv("RBI_VIDEO_RESOLUTION", "1920x1080") + "@" + rbiEnv("RBI_VIDEO_FPS", "30"),
		// HIGH-QUALITY stream: override neko's ~2 Mbps/25fps default VP8 pipeline.
		"-e", "NEKO_CAPTURE_VIDEO_PIPELINE=" + rbiVideoPipeline(),
		"-e", "NEKO_MEMBER_PROVIDER=multiuser",
		"-e", "NEKO_MEMBER_MULTIUSER_USER_PASSWORD=user",
		"-e", "NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD=admin",
		"-e", "NEKO_SESSION_IMPLICIT_HOSTING=true",
		"-e", "NEKO_WEBRTC_ICELITE=1",
		"-e", "NEKO_WEBRTC_NAT1TO1=" + rbiEnv("RBI_NAT1TO1", "127.0.0.1"),
		"-e", "NEKO_WEBRTC_UDPMUX=" + strconv.Itoa(udpPort),
		"-e", "NEKO_WEBRTC_TCPMUX=" + strconv.Itoa(tcpMuxPort),
	}
	// Webcam passthrough: if the host has a v4l2loopback device, mount it and enable
	// neko's webcam capture so the isolated Chrome can use the client's camera (neko
	// writes the client's webcam feed into the loopback device). ONLY when the device
	// exists — otherwise --device makes the container fail to start. The mic needs no
	// device (it's a PulseAudio source enabled in neko.yaml).
	if dev := rbiEnv("RBI_WEBCAM_DEVICE", "/dev/video0"); rbiDeviceExists(dev) {
		args = append(args,
			"--device", dev+":"+dev,
			"-e", "NEKO_CAPTURE_WEBCAM_ENABLED=true",
			"-e", "NEKO_CAPTURE_WEBCAM_DEVICE="+dev,
		)
	}
	// Native-camera client: serve an updated glass-fence client dist (the one with
	// the client-side enableCamera() WebRTC send-path) by bind-mounting it over
	// /var/www, WITHOUT rebuilding the image. The server-side webcam pipeline is
	// already compiled into the prod image (dormant); only the client was missing.
	// This deploys with `go build` + an rsync of client/dist to the VM — it sidesteps
	// the corporate-VPN ghcr.io TLS-interception that makes `docker build` impossible.
	if dist := rbiEnv("RBI_CLIENT_DIST", ""); dist != "" {
		if fi, err := os.Stat(dist); err == nil && fi.IsDir() {
			args = append(args, "-v", dist+":/var/www:ro")
		}
	}
	args = append(args, rbiImage())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker run: %v: %s", err, string(out))
	}

	s := &rbiSession{id: id, name: name, url: rawURL, tcpPort: tcpPort, udpPort: udpPort,
		created: time.Now(), lastActive: time.Now()}

	if err := rbiWaitReady(tcpPort, 45*time.Second); err != nil {
		rbiTeardown(name)
		return nil, fmt.Errorf("session %s not ready: %w", id, err)
	}
	log.Printf("[rbi] launched per-session %s for %s (viewer :%d, webrtc udp :%d)", name, rawURL, tcpPort, udpPort)

	rbiMu.Lock()
	rbiSessionsByHost[host] = s
	rbiMu.Unlock()
	rbiStartGC()
	return s, nil
}

// rbiViewerPage is served in the SAME tab and immediately, transparently sends
// the client to the (branding-free, full-bleed) isolated stream — no launcher,
// no button, no new window, no login. The user just sees the site.
func rbiViewerPage(title, url string, port int) string {
	if title == "" {
		title = url
	}
	// The site's name/host for the browser TAB (so it reads "YouTube", not
	// "Glass Fence"), and its favicon — passed to the client which sets them.
	display := title
	favURL := ""
	if pu, err := neturl.Parse(url); err == nil && pu.Host != "" {
		if display == "" {
			display = pu.Host
		}
		favURL = pu.Scheme + "://" + pu.Host + "/favicon.ico"
	}
	t := html.EscapeString(display)
	// Auto-login as ADMIN (pwd matches NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD) so the
	// client connects with FULL CONTROL automatically — no login page, no "take
	// control" step. rbi_title/rbi_fav let the client show the SITE's name + icon.
	// (No embed param: on this client build embed enables EXTRA controls; the
	// dashboard chrome is instead hidden via CSS baked into the image.)
	stream := fmt.Sprintf("http://localhost:%d/?usr=rbi&pwd=admin&rbi_title=%s&rbi_fav=%s",
		port, neturl.QueryEscape(display), neturl.QueryEscape(favURL))
	// Open the isolated stream in a NEW TAB (so the user's original tab stays put);
	// fall back to same-tab if the browser blocks the popup. A click handler is the
	// reliable path when auto-open is blocked.
	return `<!doctype html><html><head><meta charset="utf-8"><title>` + t + `</title>
<style>html,body{margin:0;height:100%;background:#0b0e14;color:#cfd8e3;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center}a{color:#19bd9c}</style></head>
<body><div>Opening ` + t + `… <a id="go" href="` + html.EscapeString(stream) + `" target="_blank" rel="noopener">click here if it doesn't open</a></div>
<script>var u=` + jsString(stream) + `;var w=window.open(u,"_blank");if(!w){location.replace(u);}else{document.getElementById("go").style.display="none";}
document.getElementById("go").addEventListener("click",function(){window.open(u,"_blank");});</script></body></html>`
}

// jsString wraps our controlled stream URL as a JS string literal. It must NOT
// HTML-escape (that turned & into &amp; and broke the ?pwd= auto-login param).
func jsString(s string) string { return `"` + s + `"` }

func rbiFreeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func rbiFreeUDPPort() (int, error) {
	a, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port, nil
}

func rbiWaitReady(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	// Poll the SAME host the proxy forwards to: 127.0.0.1 on a host binary, or
	// host.docker.internal when the proxy runs in a container.
	url := fmt.Sprintf("http://%s:%d/", rbiEnv("RBI_FORWARD_HOST", "127.0.0.1"), port)
	for time.Now().Before(deadline) {
		if resp, err := client.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s", timeout)
}

func rbiContainerRunning(name string) bool {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).CombinedOutput()
	return err == nil && len(out) >= 4 && string(out[:4]) == "true"
}

func rbiTeardown(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", name).CombinedOutput(); err != nil {
		log.Printf("[rbi] teardown %s: %v: %s", name, err, string(out))
	} else {
		log.Printf("[rbi] torn down %s", name)
	}
}

func rbiStartGC() {
	rbiGCOnce.Do(func() {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for range t.C {
				ttl := rbiIdleTTL()
				now := time.Now()
				var dead []*rbiSession
				rbiMu.Lock()
				for host, s := range rbiSessionsByHost {
					if now.Sub(s.lastActive) > ttl || !rbiContainerRunning(s.name) {
						dead = append(dead, s)
						delete(rbiSessionsByHost, host)
					}
				}
				rbiMu.Unlock()
				for _, s := range dead {
					log.Printf("[rbi] GC reaping idle session %s", s.name)
					rbiTeardown(s.name)
				}
			}
		}()
	})
}
