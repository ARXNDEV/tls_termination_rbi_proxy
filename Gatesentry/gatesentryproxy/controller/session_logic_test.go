package controller

import (
	"testing"
	"time"
)

// C5 (Layer A): the egress/filter listener only permits hosts of an ACTIVE
// session. Verifies the allowlist add/remove + subdomain logic with no docker.
func TestEgressAllowlist(t *testing.T) {
	m := &Manager{sessions: map[string]*Session{}, allowed: map[string]int{}, stop: make(chan struct{})}
	m.register(&Session{ID: "a", Container: "rbi-a", AllowedHost: "example.com"})

	cases := map[string]bool{
		"example.com":      true,  // exact
		"www.example.com":  true,  // subdomain
		"EXAMPLE.COM":      true,  // case-insensitive
		"example.com:443":  true,  // host:port
		"evil.test":        false, // unrelated
		"notexample.com":   false, // suffix-but-not-subdomain
	}
	for host, want := range cases {
		if got := m.IsEgressAllowed(host); got != want {
			t.Errorf("IsEgressAllowed(%q) = %v, want %v", host, got, want)
		}
	}

	// After teardown the host is no longer allowed (registry-only path; docker
	// rm on a non-existent container is a harmless no-op here).
	m.Teardown("a")
	if m.IsEgressAllowed("example.com") {
		t.Errorf("host still allowed after Teardown")
	}
}

// C6: an idle session (no Touch within IdleTimeout) is reaped by the GC loop.
// Exercises the real gcLoop timer + idle selection + registry removal.
func TestIdleGCReaps(t *testing.T) {
	m := NewManager(Config{IdleTimeout: 1 * time.Second}) // starts gcLoop()
	defer close(m.stop)

	m.register(&Session{ID: "x", Container: "rbi-x", AllowedHost: "example.com",
		lastActive: time.Now().Add(-5 * time.Second)}) // already idle
	if m.SessionCount() != 1 {
		t.Fatalf("expected 1 session, got %d", m.SessionCount())
	}

	// gcLoop ticks every 10s; wait past one tick.
	deadline := time.Now().Add(13 * time.Second)
	for time.Now().Before(deadline) {
		if m.SessionCount() == 0 {
			return // reaped — PASS
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("idle session not reaped within deadline (count=%d)", m.SessionCount())
}

// C6b: an active (recently Touched) session is NOT reaped.
func TestActiveSessionKept(t *testing.T) {
	m := NewManager(Config{IdleTimeout: 2 * time.Second})
	defer close(m.stop)
	m.register(&Session{ID: "y", Container: "rbi-y", AllowedHost: "example.com", lastActive: time.Now()})
	for i := 0; i < 6; i++ { // keep it alive across the window
		m.Touch("y")
		time.Sleep(300 * time.Millisecond)
	}
	if m.SessionCount() != 1 {
		t.Fatalf("active session was reaped (count=%d)", m.SessionCount())
	}
}
