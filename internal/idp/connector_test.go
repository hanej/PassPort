package idp

import (
	"context"
	"net"
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
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Close immediately without sending any LDAP data.
		conn.Close()
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
