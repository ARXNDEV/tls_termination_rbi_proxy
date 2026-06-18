// Package controller manages throwaway per-session RBI browser containers.
// One container == one session == one allowed URL. The proxy calls Launch()
// instead of `docker exec rbi-open`, then Touch()/Teardown() over its life.
// It also owns the shared egress allowlist (Layer A) for the :3129 listener.
package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Session struct {
	ID          string
	Container   string
	URL         string
	AllowedHost string
	Endpoint    string // <container>:8080, reachable on the isolated net
	Browser     string
	Created     time.Time
	lastActive  time.Time
}

// Config — every field comes from rbi.env (loaded into the gatesentry process).
type Config struct {
	Image          string // RBI_IMAGE
	IsolatedNet    string // RBI_ISOLATED_NETWORK
	ProxyHost      string // RBI_PROXY_HOST
	EgressPort     string // RBI_EGRESS_PORT  <-- the RBI-OFF listener (NOT the client port)
	TurnHost       string // RBI_TURN_HOST
	TurnPort       string // RBI_TURN_PORT
	TurnSecret     string // TURN_SECRET (never logged)
	PublicIP       string // PUBLIC_IP
	EPRMin         string // NEKO_EPR_MIN
	EPRMax         string // NEKO_EPR_MAX
	DesktopScreen  string // NEKO_DESKTOP_SCREEN
	SupervisordBin string // NEKO_SUPERVISORD_BIN
	SupervisordCnf string // NEKO_SUPERVISORD_CONF
	IdleTimeout    time.Duration
	ReadyTimeout   time.Duration
}

type Manager struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]*Session
	allowed  map[string]int
	stop     chan struct{}
}

func NewManager(cfg Config) *Manager {
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.ReadyTimeout == 0 {
		cfg.ReadyTimeout = 45 * time.Second
	}
	m := &Manager{cfg: cfg, sessions: map[string]*Session{}, allowed: map[string]int{}, stop: make(chan struct{})}
	go m.gcLoop()
	return m
}

func (m *Manager) Launch(ctx context.Context, rawURL, browser string) (*Session, error) {
	host := hostFromURL(rawURL)
	if host == "" {
		return nil, fmt.Errorf("controller: cannot derive host from %q", rawURL)
	}
	if m.imageFor(browser) == "" {
		return nil, fmt.Errorf("controller: unsupported browser %q (locked to Google Chrome)", browser)
	}

	id := randID()
	name := "rbi-" + id
	user, cred := m.turnCredential(2 * time.Hour)
	// TURN-RELAY ICE (no STUN, no host candidates): the only media path off the
	// internal network. Frontend = client creds, Backend = neko server creds.
	ice := fmt.Sprintf(`[{"urls":["turn:%s:%s?transport=udp"],"username":%q,"credential":%q}]`,
		m.cfg.PublicIP, m.cfg.TurnPort, user, cred)
	epr := m.cfg.EPRMin + "-" + m.cfg.EPRMax

	args := []string{
		"run", "-d", "--rm",
		"--name", name,
		"--network", m.cfg.IsolatedNet,
		// neko's privilege-dropping desktop supervisor needs docker's DEFAULT
		// (non-privileged) cap set — CHOWN/SETUID/SETGID/DAC_OVERRIDE/... —
		// to set up the X session and chown its supervisor socket. `cap-drop=ALL`
		// broke that (supervisor.sock chown failed). So we keep the defaults and
		// add ONLY NET_ADMIN (for nftables). No SYS_ADMIN; not privileged.
		"--cap-add=NET_ADMIN",
		"--security-opt", "no-new-privileges:true", // Chrome runs --no-sandbox anyway
		"--shm-size=1g", // Chrome shared memory; not a capability.
		// ---- generic inputs the entrypoint reads (not neko-version-specific) ----
		"-e", "ALLOWED_URL=" + rawURL,
		"-e", "PROXY_HOST=" + m.cfg.ProxyHost,
		"-e", "PROXY_PORT=" + m.cfg.EgressPort, // <-- EGRESS (RBI-OFF) port, not the client port
		"-e", "TURN_HOST=" + m.cfg.TurnHost,
		"-e", "TURN_PORT=" + m.cfg.TurnPort,
		"-e", "NEKO_SUPERVISORD_BIN=" + m.cfg.SupervisordBin,
		"-e", "NEKO_SUPERVISORD_CONF=" + m.cfg.SupervisordCnf,
		// ---- NEKO-V3 env var NAMES (THE place to reconcile names with your image) ----
		"-e", "NEKO_DESKTOP_SCREEN=" + m.cfg.DesktopScreen,
		"-e", "NEKO_MEMBER_PROVIDER=multiuser",
		"-e", "NEKO_MEMBER_MULTIUSER_USER_PASSWORD=" + id,
		"-e", "NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD=" + id + "-a",
		"-e", "NEKO_SESSION_IMPLICIT_HOSTING=true",
		"-e", "NEKO_WEBRTC_EPR=" + epr,
		"-e", "NEKO_WEBRTC_ICELITE=false", // relay model
		"-e", "NEKO_WEBRTC_ICESERVERS_FRONTEND=" + ice,
		"-e", "NEKO_WEBRTC_ICESERVERS_BACKEND=" + ice,
		m.imageFor(browser),
	}

	runCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, "docker", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("controller: docker run failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("[rbi] launched session %s (%s) for %s", id, name, host)

	sess := &Session{ID: id, Container: name, URL: rawURL, AllowedHost: host,
		Endpoint: name + ":8080", Browser: browser, Created: time.Now(), lastActive: time.Now()}
	m.register(sess) // register before wait so the egress allowlist permits the boot fetch

	if err := m.waitReady(ctx, sess.Endpoint); err != nil {
		m.Teardown(id) // fail closed: never leave a half-up session
		return nil, fmt.Errorf("controller: session %s not ready: %w", id, err)
	}
	log.Printf("[rbi] session %s ready at %s", id, sess.Endpoint)
	return sess, nil
}

func (m *Manager) Teardown(id string) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
		if h := sess.AllowedHost; h != "" && m.allowed[h] > 0 {
			if m.allowed[h]--; m.allowed[h] <= 0 {
				delete(m.allowed, h)
			}
		}
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", sess.Container).CombinedOutput(); err != nil {
		log.Printf("[rbi] teardown %s: %v: %s", id, err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[rbi] torn down session %s", id)
	}
}

func (m *Manager) Touch(id string) {
	m.mu.Lock()
	if s, ok := m.sessions[id]; ok {
		s.lastActive = time.Now()
	}
	m.mu.Unlock()
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

// SessionCount is exposed for tests/metrics.
func (m *Manager) SessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// IsEgressAllowed: the :3129 listener calls this so isolated browsers reach only
// hosts of an active session.
func (m *Manager) IsEgressAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for a := range m.allowed {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func (m *Manager) Shutdown() {
	close(m.stop)
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Teardown(id)
	}
}

func (m *Manager) register(s *Session) {
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.allowed[s.AllowedHost]++
	m.mu.Unlock()
}

func (m *Manager) imageFor(browser string) string {
	switch strings.ToLower(browser) {
	case "", "chrome", "google-chrome":
		return m.cfg.Image
	default:
		return ""
	}
}

func (m *Manager) waitReady(ctx context.Context, endpoint string) error {
	deadline := time.Now().Add(m.cfg.ReadyTimeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if c, err := net.DialTimeout("tcp", endpoint, time.Second); err == nil {
			c.Close()
			if resp, err := client.Get("http://" + endpoint + "/"); err == nil {
				resp.Body.Close()
				if resp.StatusCode < 500 {
					return nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s", m.cfg.ReadyTimeout)
}

func (m *Manager) gcLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			now := time.Now()
			var dead []string
			m.mu.Lock()
			for id, s := range m.sessions {
				if now.Sub(s.lastActive) > m.cfg.IdleTimeout {
					dead = append(dead, id)
				}
			}
			m.mu.Unlock()
			for _, id := range dead {
				log.Printf("[rbi] GC reaping idle session %s", id)
				m.Teardown(id)
			}
		}
	}
}

func (m *Manager) turnCredential(ttl time.Duration) (user, cred string) {
	user = fmt.Sprintf("%d:rbi", time.Now().Add(ttl).Unix())
	mac := hmac.New(sha1.New, []byte(m.cfg.TurnSecret))
	mac.Write([]byte(user))
	return user, base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hostFromURL(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSpace(s))
}
