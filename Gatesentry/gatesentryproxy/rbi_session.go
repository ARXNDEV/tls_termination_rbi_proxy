package gatesentryproxy

// Per-session RBI: every isolated navigation launches a FRESH throwaway container
// (a complete Chromium, kiosk-locked to the one URL) published on its own host
// port, and the client opens that session's stream in a NEW window. Idle sessions
// are reaped. This replaces the old single shared `docker exec rbi-open` flow.

import (
	"context"
	"encoding/json"
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

	// viewers counts live viewer WebSocket connections (neko signaling channels)
	// for this session. The container's life is tied to it: when the last viewer
	// disconnects (tab closed/reloaded/crashed) the container is torn down after a
	// short grace window. teardownTimer is the pending grace timer, if any.
	viewers       int
	teardownTimer *time.Timer
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
// SOFTWARE ENCODE ONLY (no GPU): the container has CPU to spare and media flows
// over loopback (NAT1TO1=127.0.0.1, no bandwidth limit), so we raise bitrate/fps/
// quality well above neko's blocky ~2 Mbps VP8 @25fps default.
//
// Codec is selectable via RBI_VIDEO_CODEC (default vp8):
//
//	vp8  (default) — libvpx realtime. Most pion-reliable, proven on this stack.
//	h264 / x264    — x264 tune=zerolatency. Best quality-per-bit + lowest latency
//	                 for screen content on CPU; this is the spec's primary codec.
//	                 Opt-in because it needs the client to negotiate H264.
//	vp9            — better quality/bit than VP8 but pricier in software.
//
// Common front-end for all codecs: a leaky queue caps latency to ~1 frame — if the
// encoder can't keep up we DROP the stale frame rather than grow a backlog (smooth
// pacing over resolution, per the perf targets).
//
// Tunables (no rebuild):
//   RBI_VIDEO_BITRATE  bits/s, default 8000000 (8 Mbps)
//   RBI_VIDEO_FPS      frames/s, default 30 (also sets the X display refresh)
//   RBI_VIDEO_CPU_USED vpx speed/quality 0=best..16=fastest (vp8 default 2, vp9 8)
//   RBI_X264_PRESET    x264 speed-preset, default veryfast (downshift: superfast/ultrafast)
// rbiVideoCodec normalizes RBI_VIDEO_CODEC to the codec name neko expects
// (vp8/vp9/h264). Keep this in sync with the switch in rbiVideoPipeline.
func rbiVideoCodec() string {
	switch strings.ToLower(strings.TrimSpace(rbiEnv("RBI_VIDEO_CODEC", "vp8"))) {
	case "h264", "x264":
		return "h264"
	case "vp9":
		return "vp9"
	default:
		return "vp8"
	}
}

func rbiVideoPipeline() string {
	codec := strings.ToLower(strings.TrimSpace(rbiEnv("RBI_VIDEO_CODEC", "vp8")))
	br := rbiEnv("RBI_VIDEO_BITRATE", "8000000")
	fps := rbiEnv("RBI_VIDEO_FPS", "30")

	// leaky=downstream + small max-buffers: always encode the FRESHEST frame; never
	// queue a backlog that would show up as rubber-band lag. {display} is substituted
	// by neko with the container's X display when this is fed via capture.video.pipelines.
	src := "ximagesrc display-name={display} show-pointer=false use-damage=false" +
		" ! capsfilter caps=video/x-raw,framerate=" + fps + "/1 name=framerate" +
		" ! videoconvert ! queue leaky=downstream max-buffers=2"

	switch codec {
	case "h264", "x264":
		// CBR + capped keyframe interval (~2s); zerolatency disables B-frames and
		// lookahead so every frame ships immediately. bitrate is in kbps.
		return src +
			" ! x264enc name=encoder tune=zerolatency speed-preset=" + rbiEnv("RBI_X264_PRESET", "veryfast") +
			" bitrate=" + rbiBitsToKbps(br) + " pass=cbr key-int-max=" + rbiKeyInt(fps) +
			" bframes=0 sliced-threads=true threads=8 aud=true" +
			" ! video/x-h264,stream-format=byte-stream,profile=constrained-baseline" +
			" ! appsink name=appsink"
	case "vp9":
		return src +
			" ! vp9enc name=encoder target-bitrate=" + br + " end-usage=cbr deadline=1" +
			" cpu-used=" + rbiEnv("RBI_VIDEO_CPU_USED", "8") + " threads=8 tile-columns=2 row-mt=true" +
			" keyframe-max-dist=" + rbiKeyInt(fps) + " min-quantizer=2 max-quantizer=24" +
			" ! appsink name=appsink"
	default: // vp8
		return src +
			" ! vp8enc name=encoder target-bitrate=" + br + " end-usage=cbr threads=8 deadline=1" +
			" buffer-size=12288 keyframe-max-dist=30 cpu-used=" + rbiEnv("RBI_VIDEO_CPU_USED", "2") +
			" undershoot=95 buffer-initial-size=6144 buffer-optimal-size=9216" +
			" min-quantizer=2 max-quantizer=20" +
			" ! appsink name=appsink"
	}
}

// rbiVideoPipelinesJSON wraps rbiVideoPipeline() as the JSON that neko's
// capture.video.pipelines (plural) flag expects — fed via NEKO_CAPTURE_VIDEO_PIPELINES.
//
// IMPORTANT: this is the override that ACTUALLY applies. neko ignores the singular
// capture.video.pipeline whenever pipelines is set, and the rbi-chrome image's
// neko-capture.yaml sets pipelines — so the old singular env was a silent no-op
// (the container ran the yaml's 2 Mbps/cpu-used=6 VP8). The plural flag (env/flag)
// overrides the config file in viper, so this restores real, no-rebuild control.
//
// The JSON is decoded by json.Unmarshal straight into neko's VideoConfig, which has
// NO json tags — so keys MUST be Go field names (GstPipeline/ShowPointer), NOT the
// yaml's snake_case. The pipeline id "main" matches neko-capture.yaml's ids: [main].
func rbiVideoPipelinesJSON() string {
	type vcfg struct {
		GstPipeline string `json:"GstPipeline"`
		ShowPointer bool   `json:"ShowPointer"`
	}
	b, err := json.Marshal(map[string]vcfg{"main": {GstPipeline: rbiVideoPipeline(), ShowPointer: false}})
	if err != nil {
		return "{}"
	}
	return string(b)
}

// rbiBitsToKbps converts a bits/s string to kbps (x264enc's bitrate unit).
func rbiBitsToKbps(bits string) string {
	if n, err := strconv.Atoi(strings.TrimSpace(bits)); err == nil && n > 0 {
		return strconv.Itoa(n / 1000)
	}
	return "8000"
}

// rbiKeyInt returns a ~2-second keyframe interval (in frames) for the given fps.
func rbiKeyInt(fps string) string {
	if n, err := strconv.Atoi(strings.TrimSpace(fps)); err == nil && n > 0 {
		return strconv.Itoa(n * 2)
	}
	return "60"
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
		// Reusing a still-running container (e.g. tab reopened within the close
		// grace, or a concurrent asset request): cancel any pending teardown so the
		// grace timer doesn't kill a session that's coming back to life.
		if s.teardownTimer != nil {
			s.teardownTimer.Stop()
			s.teardownTimer = nil
		}
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
		"-e", "NEKO_MEMBER_PROVIDER=multiuser",
		"-e", "NEKO_MEMBER_MULTIUSER_USER_PASSWORD=user",
		"-e", "NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD=admin",
		"-e", "NEKO_SESSION_IMPLICIT_HOSTING=true",
		"-e", "NEKO_WEBRTC_ICELITE=1",
		"-e", "NEKO_WEBRTC_NAT1TO1=" + rbiEnv("RBI_NAT1TO1", "127.0.0.1"),
		// TCP-ONLY WebRTC: the corporate network THROTTLES UDP (mic works, but the camera's
		// upstream video chokes to ~1fps over UDP). UDP still *connects*, so the client won't
		// fall back to TCP on its own. Dropping UDPMUX forces all WebRTC media (screen+mic+
		// camera) onto the un-throttled TCP mux → native camera gets full fps. Set
		// RBI_WEBRTC_ALLOW_UDP=1 to restore UDP (lower latency) on networks that don't throttle.
		"-e", "NEKO_WEBRTC_TCPMUX=" + strconv.Itoa(tcpMuxPort),
	}
	if rbiEnv("RBI_WEBRTC_ALLOW_UDP", "0") == "1" {
		args = append(args, "-e", "NEKO_WEBRTC_UDPMUX="+strconv.Itoa(udpPort))
	}
	// HIGH-QUALITY stream override is OPT-IN. The deployed neko's pipelines-JSON
	// schema must be confirmed on a throwaway container first — a mismatched schema
	// yields an empty encoder (`! name=encoder`) → GStreamer syntax error → black
	// stream. Default OFF = neko uses its built-in neko-capture.yaml (proven VP8).
	// Enable with RBI_VIDEO_PIPELINE_OVERRIDE=1 once the format is verified, then
	// tune via RBI_VIDEO_CODEC / RBI_VIDEO_BITRATE / RBI_VIDEO_FPS / RBI_VIDEO_CPU_USED.
	if rbiEnv("RBI_VIDEO_PIPELINE_OVERRIDE", "0") == "1" {
		args = append(args,
			"-e", "NEKO_CAPTURE_VIDEO_CODEC="+rbiVideoCodec(),
			"-e", "NEKO_CAPTURE_VIDEO_PIPELINES="+rbiVideoPipelinesJSON(),
		)
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

	// Apply post-launch tuning (page zoom for all sites; blocklist relax for
	// multi-domain sites like Meet/Teams), then one Chrome reload.
	rbiTuneContainer(name, host)

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

// rbiCloseGrace is how long after the LAST viewer disconnects we wait before
// destroying the container. A small grace (default 2s) tolerates page reloads
// and brief WS reconnects without a cold-start respawn, while still feeling
// immediate to the user. Set RBI_CLOSE_GRACE_MS=0 for instant teardown.
func rbiCloseGrace() time.Duration {
	if v := strings.TrimSpace(rbiEnv("RBI_CLOSE_GRACE_MS", "")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return 2 * time.Second
}

// rbiViewerAttach registers a live viewer WebSocket for the session bound to the
// given container (viewer) port, and cancels any pending teardown — the tab is
// (back) open. Returns the session, or nil if the port isn't an RBI session
// (so non-RBI websockets are a no-op). LIFECYCLE-CRITICAL.
func rbiViewerAttach(port int) *rbiSession {
	rbiMu.Lock()
	defer rbiMu.Unlock()
	for _, s := range rbiSessionsByHost {
		if s.tcpPort == port {
			if s.teardownTimer != nil {
				s.teardownTimer.Stop()
				s.teardownTimer = nil
			}
			s.viewers++
			s.lastActive = time.Now()
			return s
		}
	}
	return nil
}

// rbiViewerDetach drops a viewer WebSocket. When the LAST viewer for the session
// leaves, the container is torn down after rbiCloseGrace(). This is the immediate
// per-tab teardown path: closing the tab drops neko's signaling WS, which unwinds
// HandleWebsocketConnection and lands here, so the container — and the camera/mic
// it was holding — is destroyed promptly. The GC reaper is only a backstop.
// LIFECYCLE-CRITICAL.
func rbiViewerDetach(port int) {
	rbiMu.Lock()
	defer rbiMu.Unlock()
	var host string
	var s *rbiSession
	for h, x := range rbiSessionsByHost {
		if x.tcpPort == port {
			host, s = h, x
			break
		}
	}
	if s == nil {
		return
	}
	if s.viewers > 0 {
		s.viewers--
	}
	if s.viewers > 0 {
		return // other tabs/viewers still attached to this container
	}

	name := s.name
	grace := rbiCloseGrace()
	if grace <= 0 {
		delete(rbiSessionsByHost, host)
		go rbiTeardown(name)
		return
	}
	if s.teardownTimer != nil {
		s.teardownTimer.Stop()
	}
	s.teardownTimer = time.AfterFunc(grace, func() {
		rbiMu.Lock()
		cur, ok := rbiSessionsByHost[host]
		// Bail if the session was replaced, or a viewer reattached during grace.
		if !ok || cur != s || cur.viewers > 0 {
			rbiMu.Unlock()
			return
		}
		delete(rbiSessionsByHost, host)
		rbiMu.Unlock()
		log.Printf("[rbi] last viewer left; tearing down %s", name)
		rbiTeardown(name)
	})
}

// rbiMultiDomainHost reports whether host is a multi-domain web app whose
// resources span domains the single-host kiosk allowlist would block (Meet pulls
// accounts.google.com / googlevideo / gstatic, Teams pulls *.office.net, etc.).
// For these we relax URLBlocklist after launch. Tunable via RBI_RELAX_HOSTS.
func rbiMultiDomainHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, h := range strings.Split(rbiEnv("RBI_RELAX_HOSTS",
		"meet.google.com,teams.microsoft.com,teams.live.com"), ",") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" && (host == h || strings.HasSuffix(host, "."+h)) {
			return true
		}
	}
	return false
}

// rbiDeviceScale is the Chrome device-scale-factor (page zoom) for the isolated
// browser. The image bakes 1.25; default here is 0.75 (smaller, more fits).
// Tunable via RBI_DEVICE_SCALE.
func rbiDeviceScale() string {
	if s := strings.TrimSpace(rbiEnv("RBI_DEVICE_SCALE", "0.75")); s != "" {
		return s
	}
	return "0.75"
}

// rbiTuneContainer applies post-launch fixes that the prebuilt image can't do
// (it's rebuild-locked behind the corporate VPN), then restarts Chromium ONCE so
// they take effect:
//   - sets the page zoom (device-scale-factor) to rbiDeviceScale() — all sites;
//   - for multi-domain sites (Meet/Teams) clears URLBlocklist so cross-domain
//     resources (accounts.google.com, googlevideo, *.office.net) load instead of
//     hitting the single-host kiosk allowlist and showing "page blocked".
// Best-effort; failures are logged, not fatal.
func rbiTuneContainer(name, host string) {
	scale := rbiDeviceScale()
	sed := "sed -i -E 's/force-device-scale-factor=[0-9.]+/force-device-scale-factor=" + scale +
		"/g' /etc/neko/supervisord/chromium.conf 2>/dev/null || true"
	_ = exec.Command("docker", "exec", name, "sh", "-c", sed).Run()

	relax := rbiMultiDomainHost(host)
	if relax {
		const py = "import glob,json\n" +
			"for f in glob.glob('/etc/chromium/policies/managed/*.json')+glob.glob('/etc/opt/chrome/policies/managed/*.json'):\n" +
			"    try:\n" +
			"        d=json.load(open(f)); d['URLBlocklist']=[]; json.dump(d,open(f,'w'))\n" +
			"    except Exception: pass\n"
		if out, err := exec.Command("docker", "exec", name, "python3", "-c", py).CombinedOutput(); err != nil {
			log.Printf("[rbi] relax kiosk %s: %v: %s", name, err, string(out))
		}
	}
	// One restart picks up both the zoom and the relaxed policy.
	_ = exec.Command("docker", "exec", name, "supervisorctl", "restart", "chromium").Run()
	log.Printf("[rbi] tuned %s (scale=%s, relax=%v)", name, scale, relax)
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
					// Reconciliation backstop. The primary teardown path is
					// rbiViewerDetach (WS close). Here we only catch leaks:
					//   - the container died out from under us, OR
					//   - a session with NO viewer attached has gone idle past TTL
					//     (e.g. launched but the viewer tab never connected).
					// An attached viewer is NEVER reaped on idle — an open-but-quiet
					// tab must not have its container pulled.
					running := rbiContainerRunning(s.name)
					if !running || (s.viewers == 0 && now.Sub(s.lastActive) > ttl) {
						if s.teardownTimer != nil {
							s.teardownTimer.Stop()
						}
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
