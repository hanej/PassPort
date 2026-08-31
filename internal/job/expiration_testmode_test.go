package job

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// fakeSMTPCaptureServer starts a minimal SMTP server that records every
// RCPT TO address it receives, so tests can assert who an email was
// actually addressed to.
func fakeSMTPCaptureServer(t *testing.T) (addr string, recipients *[]string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting fake SMTP server: %v", err)
	}
	got := make([]string, 0)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			serveOneCapturingSMTP(conn, &got)
		}
	}()
	return ln.Addr().String(), &got, func() { _ = ln.Close(); <-done }
}

func serveOneCapturingSMTP(conn net.Conn, recipients *[]string) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)
	send := func(s string) {
		_, _ = fmt.Fprintf(w, "%s\r\n", s)
		_ = w.Flush()
	}
	send("220 127.0.0.1 SMTP Service Ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			send("250-127.0.0.1 Hello")
			send("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM"):
			send("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			*recipients = append(*recipients, line)
			send("250 OK")
		case upper == "DATA":
			send("354 Start mail input; end with <CRLF>.<CRLF>")
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
			}
			send("250 OK: Message queued")
		case upper == "QUIT":
			send("221 Bye")
			return
		default:
			send("500 Command unrecognized")
		}
	}
}

// testSMTPConfigAt saves an enabled SMTP config pointed at a specific host/port.
func testSMTPConfigAt(t *testing.T, database *db.DB, host, port string) {
	t.Helper()
	cfg := map[string]any{
		"host":    host,
		"port":    port,
		"enabled": true,
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
	}); err != nil {
		t.Fatalf("saving smtp config: %v", err)
	}
}

func TestRunForIDPManualTest_RedirectsToTestRecipient(t *testing.T) {
	addr, recipients, stop := fakeSMTPCaptureServer(t)
	defer stop()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting fake SMTP addr: %v", err)
	}

	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfigAt(t, database, host, port)
	testEmailTemplate(t, database)

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDPManualTest(context.Background(), "corp-ad", "tester@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 notification sent, got %d", count)
	}
	if len(*recipients) != 1 {
		t.Fatalf("expected 1 RCPT TO command, got %d: %v", len(*recipients), *recipients)
	}
	got := (*recipients)[0]
	if !strings.Contains(got, "tester@example.com") {
		t.Errorf("expected RCPT TO the test recipient, got %q", got)
	}
	if strings.Contains(got, "jdoe@example.com") {
		t.Errorf("real user email leaked into RCPT TO: %q", got)
	}
}

// TestRunForIDPManualTest_CapsAtOnePerType verifies that when several users
// match, test mode still sends only one warning email and one expired email
// (not one per matched user).
func TestRunForIDPManualTest_CapsAtOnePerType(t *testing.T) {
	addr, recipients, stop := fakeSMTPCaptureServer(t)
	defer stop()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting fake SMTP addr: %v", err)
	}

	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              true,
		CronSchedule:         "0 0 * * *",
		DaysBeforeExpiration: 14,
		DaysAfterExpiration:  -1,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}
	testSMTPConfigAt(t, database, host, port)
	testEmailTemplate(t, database)
	testExpiredEmailTemplate(t, database)

	// Two users due for a warning, two users already expired.
	warningUsers := []*ldap.Entry{
		adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80),
		adUserEntry("cn=asmith,dc=example,dc=com", "asmith", "asmith@example.com", 82),
	}
	expiredUsers := []*ldap.Entry{
		adUserEntry("cn=bwong,dc=example,dc=com", "bwong", "bwong@example.com", 100),
		adUserEntry("cn=cchen,dc=example,dc=com", "cchen", "cchen@example.com", 105),
	}
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},       // warning maxPwdAge
			{result: &ldap.SearchResult{Entries: warningUsers}}, // warning search
			{result: maxPwdAgeEntry("dc=example,dc=com")},       // expired maxPwdAge
			{result: &ldap.SearchResult{Entries: expiredUsers}}, // expired search
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDPManualTest(context.Background(), "corp-ad", "tester@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 notifications sent (1 warning + 1 expired), got %d", count)
	}
	if len(*recipients) != 2 {
		t.Fatalf("expected 2 RCPT TO commands, got %d: %v", len(*recipients), *recipients)
	}
	for _, r := range *recipients {
		if !strings.Contains(r, "tester@example.com") {
			t.Errorf("expected RCPT TO the test recipient, got %q", r)
		}
	}
}

// testExpiredEmailTemplate saves a password_expired email template.
func testExpiredEmailTemplate(t *testing.T, database *db.DB) {
	t.Helper()
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "password_expired",
		Subject:      "Password Expired for {{.Username}}",
		BodyHTML:     "<p>Hello {{.Username}}, your password expired on {{.ExpirationDate}}.</p>",
	}); err != nil {
		t.Fatalf("saving email template: %v", err)
	}
}

func TestRunForIDPManualTest_DisabledConfigProceeds(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testCreateIDP(t, database, "corp-ad")

	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              false,
		CronSchedule:         "0 * * * *",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}

	// Like RunForIDPManual, the disabled check must be bypassed in test mode too.
	_, err := n.RunForIDPManualTest(context.Background(), "corp-ad", "tester@example.com")
	if err == nil {
		t.Fatal("expected an error (SMTP not configured), got nil")
	}
	if strings.Contains(err.Error(), "disabled") {
		t.Errorf("RunForIDPManualTest should bypass disabled check, but got: %v", err)
	}
}
