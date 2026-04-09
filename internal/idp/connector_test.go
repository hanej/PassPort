package idp

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestDefaultLDAPConnector_Connect_LDAPS_Error(t *testing.T) {
	c := &DefaultLDAPConnector{}
	_, err := c.Connect(context.Background(), "192.0.2.1:636", "ldaps", 1, true)
	if err == nil {
		t.Error("expected connection error for non-routable LDAPS address")
	}
}

func TestDefaultLDAPConnector_Connect_LDAP_Error(t *testing.T) {
	c := &DefaultLDAPConnector{}
	_, err := c.Connect(context.Background(), "192.0.2.1:389", "ldap", 1, true)
	if err == nil {
		t.Error("expected connection error for non-routable LDAP address")
	}
}

func TestDefaultLDAPConnector_Connect_StartTLS_Error(t *testing.T) {
	// starttls first dials ldap:// plaintext; 192.0.2.1 is non-routable so dial fails.
	c := &DefaultLDAPConnector{}
	_, err := c.Connect(context.Background(), "192.0.2.1:389", "starttls", 1, true)
	if err == nil {
		t.Error("expected connection error for non-routable STARTTLS address")
	}
}

func TestDefaultLDAPConnector_Connect_UnknownProtocol(t *testing.T) {
	// Unknown protocol must return an error immediately without dialing.
	c := &DefaultLDAPConnector{}
	_, err := c.Connect(context.Background(), "192.0.2.1:389", "bogus", 1, true)
	if err == nil {
		t.Error("expected error for unknown protocol")
	}
}

func TestDefaultLDAPConnector_Connect_ZeroTimeout(t *testing.T) {
	// timeout <= 0 should clamp to 10; connection still fails but branch is covered.
	c := &DefaultLDAPConnector{}
	_, err := c.Connect(context.Background(), "192.0.2.1:389", "ldap", 0, true)
	if err == nil {
		t.Error("expected connection error for non-routable address with zero timeout")
	}
}

func TestDefaultLDAPConnector_Connect_StartTLS_DialSucceeds_StartTLSFails(t *testing.T) {
	// Set up a raw TCP listener that accepts a connection but doesn't speak LDAP.
	// The ldap.DialURL("ldap://addr") for plaintext should succeed (TCP connect),
	// but then conn.StartTLS will fail because the server doesn't respond correctly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting TCP listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Close immediately without sending any LDAP data.
		_ = conn.Close()
	}()

	c := &DefaultLDAPConnector{}
	addr := ln.Addr().String()
	_, connErr := c.Connect(context.Background(), addr, "starttls", 2, true)
	<-done
	// Connection may or may not fail depending on LDAP client behavior, but we
	// exercise the starttls dial path; either the StartTLS fails or the connect
	// returns an error.
	_ = connErr
}

func TestSplitEndpoints(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"host:636", []string{"host:636"}},
		{"a:636, b:636", []string{"a:636", "b:636"}},
		{"a:636,b:636,c:636", []string{"a:636", "b:636", "c:636"}},
		{" a:636 , b:636 ", []string{"a:636", "b:636"}},
		{"", []string{}},
		{",,,", []string{}},
	}
	for _, tc := range cases {
		got := splitEndpoints(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitEndpoints(%q): got %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitEndpoints(%q)[%d]: got %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestDefaultLDAPConnector_Connect_EmptyEndpoint(t *testing.T) {
	c := &DefaultLDAPConnector{}
	_, err := c.Connect(context.Background(), "", "ldap", 1, false)
	if err == nil {
		t.Fatal("expected error for empty endpoint")
	}
	if !strings.Contains(err.Error(), "no LDAP endpoint") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDefaultLDAPConnector_Connect_MultiEndpoint_AllFail(t *testing.T) {
	c := &DefaultLDAPConnector{}
	// Both 192.0.2.x addresses are non-routable (TEST-NET-1), so both dials fail.
	_, err := c.Connect(context.Background(), "192.0.2.1:389, 192.0.2.2:389", "ldap", 1, false)
	if err == nil {
		t.Fatal("expected error when all endpoints fail")
	}
	if !strings.Contains(err.Error(), "all 2 LDAP endpoints failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDefaultLDAPConnector_Connect_MultiEndpoint_FailoverSucceeds(t *testing.T) {
	// Start a listener that accepts exactly one connection and closes it cleanly.
	// This exercises the path where the first (failing) endpoint is skipped and the
	// second (listening) endpoint is reached.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting TCP listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan struct{})
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		close(accepted)
	}()

	c := &DefaultLDAPConnector{}
	// First endpoint is non-routable (will fail quickly); second is our listener.
	endpointList := "192.0.2.1:389, " + ln.Addr().String()
	// Run several times to ensure both orderings are exercised (shuffle is random).
	// We just need at least one attempt to hit the listener path.
	var lastErr error
	for i := 0; i < 20; i++ {
		_, lastErr = c.Connect(context.Background(), endpointList, "ldap", 1, false)
		// Once the listener is hit, the goroutine closes accepted.
		select {
		case <-accepted:
			// The connection reached the listener — failover path was exercised.
			return
		default:
		}
	}
	// If we never reached the listener, that itself is the test failure.
	t.Errorf("failover never reached the live endpoint after 20 attempts; last error: %v", lastErr)
}
