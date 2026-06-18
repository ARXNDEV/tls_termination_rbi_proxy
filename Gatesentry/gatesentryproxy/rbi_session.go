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
	"os"
	"os/exec"
	"strconv"
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
	rbiMu            sync.Mutex
	rbiSessionsByURL = map[string]*rbiSession{}
	rbiGCOnce        sync.Once
	rbiSeq           int
)

func rbiEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func rbiImage() string   { return rbiEnv("RBI_IMAGE", "rbi-chrome-neko:latest") }
func rbiIdleTTL() time.Duration {
	if n, err := strconv.Atoi(rbiEnv("RBI_IDLE_SECONDS", "600")); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 10 * time.Minute
}

// rbiLaunchSession returns a running per-session container for rawURL, reusing an
// existing live one for the same URL or launching a fresh throwaway otherwise.
func rbiLaunchSession(rawURL string) (*rbiSession, error) {
	rbiMu.Lock()
	if s, ok := rbiSessionsByURL[rawURL]; ok && rbiContainerRunning(s.name) {
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
	id := strconv.Itoa(seq) + "-" + strconv.FormatInt(time.Now().UnixNano()%100000, 10)
	name := "rbi-sess-" + id

	args := []string{
		"run", "-d", "--rm", "--name", name,
		"-p", fmt.Sprintf("%d:8080", tcpPort),
		"-p", fmt.Sprintf("%d:%d/udp", udpPort, udpPort),
		"--cap-add=NET_ADMIN", "--security-opt", "no-new-privileges:true", "--shm-size=1g",
		"-e", "ALLOWED_URL=" + rawURL,
		// DEMO_DIRECT lets the kiosk render on hosts without the :3129 egress
		// listener (e.g. this arm64 Mac). On a production x86 host set
		// RBI_PROXY_DEMO_DIRECT=0 to keep the full Layer-B firewall + egress proxy.
		"-e", "RBI_DEMO_DIRECT=" + rbiEnv("RBI_PROXY_DEMO_DIRECT", "1"),
		"-e", "PROXY_HOST=" + rbiEnv("RBI_PROXY_HOST", "dummy"),
		"-e", "PROXY_PORT=" + rbiEnv("RBI_EGRESS_PORT", "3129"),
		"-e", "TURN_HOST=" + rbiEnv("RBI_TURN_HOST", "dummy"),
		"-e", "TURN_PORT=" + rbiEnv("RBI_TURN_PORT", "3478"),
		"-e", "NEKO_DESKTOP_SCREEN=1920x1080@30",
		"-e", "NEKO_MEMBER_PROVIDER=multiuser",
		"-e", "NEKO_MEMBER_MULTIUSER_USER_PASSWORD=user",
		"-e", "NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD=admin",
		"-e", "NEKO_SESSION_IMPLICIT_HOSTING=true",
		"-e", "NEKO_WEBRTC_ICELITE=1",
		"-e", "NEKO_WEBRTC_NAT1TO1=127.0.0.1",
		"-e", "NEKO_WEBRTC_UDPMUX=" + strconv.Itoa(udpPort),
		rbiImage(),
	}

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
	rbiSessionsByURL[rawURL] = s
	rbiMu.Unlock()
	rbiStartGC()
	return s, nil
}

// rbiViewerPage is the tiny page served to the client; it opens the session's
// stream in a NEW window (with a button fallback for popup blockers).
func rbiViewerPage(title, url string, port int) string {
	if title == "" {
		title = url
	}
	t := html.EscapeString(title)
	u := html.EscapeString(url)
	stream := fmt.Sprintf("http://localhost:%d/", port)
	win := "rbi_" + strconv.Itoa(port)
	return `<!doctype html><html><head><meta charset="utf-8"><title>` + t + ` — Isolated</title>
<style>html,body{margin:0;height:100%;background:#0b0e14;color:#e6e6e6;font-family:system-ui,-apple-system,sans-serif}
.wrap{height:100%;display:flex;align-items:center;justify-content:center}
.card{max-width:560px;text-align:center;padding:32px}
h2{font-weight:700;margin:0 0 12px}.u{color:#19bd9c;word-break:break-all}
.btn{display:inline-block;margin-top:20px;padding:14px 30px;background:#19bd9c;color:#04201a;font-weight:800;border:0;border-radius:10px;font-size:16px;cursor:pointer;text-decoration:none}
small{color:#8b97a7;display:block;margin-top:16px}</style></head>
<body><div class="wrap"><div class="card">
<h2>🛡️ Opening in an isolated browser</h2>
<p><span class="u">` + u + `</span> runs in a throwaway remote browser — you only receive video, no page code touches this device.</p>
<a class="btn" id="go" href="` + stream + `" target="` + win + `">Open isolated session ▶</a>
<small>Login: <b>user</b> / <b>admin</b> · the session is destroyed when idle.</small>
</div></div>
<script>var u=` + jsString(stream) + `,n=` + jsString(win) + `;
function open_(){window.open(u,n,"width=1300,height=860");}
try{open_();}catch(e){}
document.getElementById('go').addEventListener('click',function(e){e.preventDefault();open_();});</script>
</body></html>`
}

func jsString(s string) string { return `"` + html.EscapeString(s) + `"` }

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
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
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
				for url, s := range rbiSessionsByURL {
					if now.Sub(s.lastActive) > ttl || !rbiContainerRunning(s.name) {
						dead = append(dead, s)
						delete(rbiSessionsByURL, url)
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
