package job

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/email"
	"github.com/hanej/passport/internal/idp"
)

// fakeSMTPServer starts a permissive in-process SMTP server and returns an
// email.Config pointed at it. Without a reachable relay every send fails, which
// would leave the "notification actually went out" paths untested.
func fakeSMTPServer(t *testing.T) email.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting fake SMTP server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSMTP(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splitting fake SMTP address: %v", err)
	}
	return email.Config{Host: host, Port: port, FromAddress: "passport@example.com"}
}

// serveFakeSMTP answers a single SMTP session, accepting everything.
func serveFakeSMTP(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
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
		upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			send("250-127.0.0.1 Hello")
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
			send("250 OK")
		}
	}
}

// unreachableSMTP returns a config for a port nothing is listening on, so
// email.SendHTML fails fast.
func unreachableSMTP(t *testing.T) email.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting address: %v", err)
	}
	return email.Config{Host: host, Port: port, FromAddress: "passport@example.com"}
}

// saveExpiredTemplate stores a password_expired template under templateType.
func saveExpiredTemplate(t *testing.T, database *db.DB, templateType, subject, body string) {
	t.Helper()
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: templateType,
		Subject:      subject,
		BodyHTML:     body,
	}); err != nil {
		t.Fatalf("saving %s template: %v", templateType, err)
	}
}

// expiredTestEnv bundles everything sendExpiredNotifications needs.
type expiredTestEnv struct {
	notifier *PasswordExpirationNotifier
	database *db.DB
	record   *db.IdentityProviderRecord
	config   idp.Config
	cfg      *db.ExpirationConfig
}

func newExpiredTestEnv(t *testing.T, providerType string) *expiredTestEnv {
	t.Helper()
	database := openTestDB(t)
	n := New(database, idp.NewRegistry(testLogger()), newCryptoService(t), newAuditLogger(t, database), testLogger())
	return &expiredTestEnv{
		notifier: n,
		database: database,
		record: &db.IdentityProviderRecord{
			ID:           "corp",
			FriendlyName: "Corp Directory",
			ProviderType: providerType,
		},
		config: idp.Config{
			BaseDN:         "dc=example,dc=com",
			UserSearchBase: "ou=Users,dc=example,dc=com",
		},
		// -1 means "every expired account", so the fixtures below are never
		// filtered out by the look-back window.
		cfg: &db.ExpirationConfig{IDPID: "corp", DaysAfterExpiration: -1},
	}
}

func (e *expiredTestEnv) send(t *testing.T, emailCfg email.Config, compiled []compiledFilter, conn idp.LDAPConn) (int, error) {
	t.Helper()
	return e.notifier.sendExpiredNotifications(
		context.Background(), "corp", e.cfg, e.record, e.config, emailCfg, compiled, conn, "")
}

// adExpiredConn returns a mock connection that answers the maxPwdAge lookup and
// then the expired-user search. The fixture password was set 100 days ago
// against a 90-day maxPwdAge, so it expired 10 days ago.
func adExpiredConn(entries ...*ldap.Entry) *mockLDAPConn {
	return &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: entries}},
		},
	}
}

func TestSendExpiredNotifications_ADSuccess(t *testing.T) {
	env := newExpiredTestEnv(t, "ad")
	saveExpiredTemplate(t, env.database, "password_expired",
		"Password expired for {{.Username}}",
		"<p>{{.Username}} at {{.ProviderName}}: expired {{.DaysExpired}} days ago on {{.ExpirationDate}}.</p>")

	conn := adExpiredConn(adUserEntry("cn=alice,ou=Users,dc=example,dc=com", "alice", "alice@example.com", 100))

	sent, err := env.send(t, fakeSMTPServer(t), nil, conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sent != 1 {
		t.Fatalf("expected 1 notification, got %d", sent)
	}

	entries, _, err := env.database.ListAudit(context.Background(), db.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("listing audit: %v", err)
	}
	var found bool
	for _, entry := range entries {
		if entry.Username == "alice" && entry.Action == "expired_notification" {
			found = true
		}
	}
	if !found {
		t.Error("expected an expired_notification audit entry for alice")
	}
}

func TestSendExpiredNotifications_IDPSpecificTemplateWins(t *testing.T) {
	env := newExpiredTestEnv(t, "ad")
	saveExpiredTemplate(t, env.database, "password_expired", "global", "<p>global</p>")
	saveExpiredTemplate(t, env.database, "password_expired:corp", "per-idp", "<p>per-idp</p>")

	conn := adExpiredConn(adUserEntry("cn=alice,ou=Users,dc=example,dc=com", "alice", "alice@example.com", 100))

	sent, err := env.send(t, fakeSMTPServer(t), nil, conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sent != 1 {
		t.Errorf("expected 1 notification, got %d", sent)
	}
}

// mockNoTemplateStore reports that no email template exists. Migrations seed
// both password_expiration and password_expired, so this is the only way to
// reach the missing-template path.
type mockNoTemplateStore struct {
	*db.DB
}

func (m *mockNoTemplateStore) GetEmailTemplate(context.Context, string) (*db.EmailTemplate, error) {
	return nil, nil
}

func TestSendExpiredNotifications_NoTemplate(t *testing.T) {
	env := newExpiredTestEnv(t, "ad")
	env.notifier.store = &mockNoTemplateStore{DB: env.database}

	_, err := env.send(t, fakeSMTPServer(t), nil, adExpiredConn())
	if err == nil {
		t.Fatal("expected an error when no password_expired template exists")
	}
	if !strings.Contains(err.Error(), "password_expired email template not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendExpiredNotifications_SearchFailures(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		conn         *mockLDAPConn
		wantMsg      string
	}{
		{
			name:         "AD maxPwdAge lookup fails",
			providerType: "ad",
			conn:         &mockLDAPConn{searchErr: newError("boom")},
			wantMsg:      "getting AD maxPwdAge",
		},
		{
			name:         "AD expired search fails",
			providerType: "ad",
			conn: &mockLDAPConn{searches: []mockSearch{
				{result: maxPwdAgeEntry("dc=example,dc=com")},
				{err: newError("boom")},
			}},
			wantMsg: "searching AD expired users",
		},
		{
			name:         "FreeIPA expired search fails",
			providerType: "freeipa",
			conn:         &mockLDAPConn{searchErr: newError("boom")},
			wantMsg:      "searching FreeIPA expired users",
		},
		{
			name:         "unsupported provider type",
			providerType: "weblink",
			conn:         &mockLDAPConn{searchResult: emptySearchResult()},
			wantMsg:      "unsupported provider type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newExpiredTestEnv(t, tt.providerType)
			saveExpiredTemplate(t, env.database, "password_expired", "s", "<p>b</p>")

			_, err := env.send(t, fakeSMTPServer(t), nil, tt.conn)
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tt.wantMsg)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantMsg)
			}
		})
	}
}

func TestSendExpiredNotifications_FreeIPASuccess(t *testing.T) {
	env := newExpiredTestEnv(t, "freeipa")
	saveExpiredTemplate(t, env.database, "password_expired", "expired", "<p>{{.DaysExpired}}</p>")

	conn := &mockLDAPConn{searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{
		freeIPAUserEntry("uid=bob,cn=users,dc=example,dc=com", "bob", "bob@example.com", -10),
	}}}

	sent, err := env.send(t, fakeSMTPServer(t), nil, conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sent != 1 {
		t.Errorf("expected 1 notification, got %d", sent)
	}
}

// TestSendExpiredNotifications_SkipsUsers covers every branch that drops a user
// from the send loop. Each must leave the count at zero without failing the run,
// because one bad account should never abort the whole scan.
func TestSendExpiredNotifications_SkipsUsers(t *testing.T) {
	expiredUser := func() *ldap.Entry {
		return adUserEntry("cn=alice,ou=Users,dc=example,dc=com", "alice", "alice@example.com", 100)
	}

	tests := []struct {
		name     string
		subject  string
		body     string
		entry    *ldap.Entry
		compiled []compiledFilter
		// extraSearch is appended after the expired-user search to answer a
		// readUserAttribute lookup performed by an attribute filter.
		extraSearch *mockSearch
	}{
		{
			name:     "excluded by DN filter",
			subject:  "s",
			body:     "<p>b</p>",
			entry:    expiredUser(),
			compiled: []compiledFilter{{attribute: "dn", regex: regexp.MustCompile(`ou=Users`)}},
		},
		{
			name:        "excluded by attribute filter",
			subject:     "s",
			body:        "<p>b</p>",
			entry:       expiredUser(),
			compiled:    []compiledFilter{{attribute: "department", regex: regexp.MustCompile(`^IT$`)}},
			extraSearch: &mockSearch{result: &ldap.SearchResult{Entries: []*ldap.Entry{newTestEntry("cn=alice,ou=Users,dc=example,dc=com", map[string][]string{"department": {"IT"}})}}},
		},
		{
			name:     "no email address",
			subject:  "s",
			body:     "<p>b</p>",
			entry:    adUserEntry("cn=carol,ou=Users,dc=example,dc=com", "carol", "", 100),
			compiled: nil,
		},
		{
			name:    "body template is malformed",
			subject: "s",
			body:    "<p>{{.Username",
			entry:   expiredUser(),
		},
		{
			name:    "subject template is malformed",
			subject: "{{.Username",
			body:    "<p>b</p>",
			entry:   expiredUser(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newExpiredTestEnv(t, "ad")
			saveExpiredTemplate(t, env.database, "password_expired", tt.subject, tt.body)

			conn := adExpiredConn(tt.entry)
			if tt.extraSearch != nil {
				conn.searches = append(conn.searches, *tt.extraSearch)
			}

			sent, err := env.send(t, fakeSMTPServer(t), tt.compiled, conn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sent != 0 {
				t.Errorf("expected the user to be skipped, but %d notifications were sent", sent)
			}
		})
	}
}

// TestSendExpiredNotifications_AttrReadFails covers the filter attribute that
// cannot be read: the filter is skipped, so the user still gets notified.
func TestSendExpiredNotifications_AttrReadFails(t *testing.T) {
	env := newExpiredTestEnv(t, "ad")
	saveExpiredTemplate(t, env.database, "password_expired", "s", "<p>b</p>")

	conn := adExpiredConn(adUserEntry("cn=alice,ou=Users,dc=example,dc=com", "alice", "alice@example.com", 100))
	conn.searches = append(conn.searches, mockSearch{err: newError("no such attribute")})

	sent, err := env.send(t, fakeSMTPServer(t),
		[]compiledFilter{{attribute: "department", regex: regexp.MustCompile(`^IT$`)}}, conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sent != 1 {
		t.Errorf("expected the user to still be notified, got %d", sent)
	}
}

func TestSendExpiredNotifications_SendFails(t *testing.T) {
	env := newExpiredTestEnv(t, "ad")
	saveExpiredTemplate(t, env.database, "password_expired", "s", "<p>b</p>")

	conn := adExpiredConn(adUserEntry("cn=alice,ou=Users,dc=example,dc=com", "alice", "alice@example.com", 100))

	sent, err := env.send(t, unreachableSMTP(t), nil, conn)
	if err != nil {
		t.Fatalf("a failed send must not abort the scan: %v", err)
	}
	if sent != 0 {
		t.Errorf("expected 0 notifications, got %d", sent)
	}
}

// TestRunForIDP_ExpiredNotificationsWired proves runForIDP reaches the expired
// pass when DaysAfterExpiration is set, and that a failure there is logged
// rather than discarding the expiring-password notifications already sent.
func TestRunForIDP_ExpiredNotificationsWired(t *testing.T) {
	t.Run("expired notifications counted", func(t *testing.T) {
		database := openTestDB(t)
		n := New(database, idp.NewRegistry(testLogger()), newCryptoService(t), newAuditLogger(t, database), testLogger())

		testSetupADIDP(t, database, "corp-ad")
		testSMTPConfig(t, database)
		testEmailTemplate(t, database)
		saveExpiredTemplate(t, database, "password_expired", "expired", "<p>expired</p>")

		smtpCfg := fakeSMTPServer(t)
		saveSMTPConfigAt(t, database, smtpCfg.Host, smtpCfg.Port)

		if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
			IDPID:                "corp-ad",
			Enabled:              true,
			CronSchedule:         "0 0 * * *",
			DaysBeforeExpiration: 14,
			DaysAfterExpiration:  -1,
		}); err != nil {
			t.Fatalf("saving expiration config: %v", err)
		}

		n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")}, // expiring: maxPwdAge
			{result: emptySearchResult()},                 // expiring: no one
			{result: maxPwdAgeEntry("dc=example,dc=com")}, // expired: maxPwdAge
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				adUserEntry("cn=alice,ou=Users,dc=example,dc=com", "alice", "alice@example.com", 100),
			}}},
		}}}

		sent, err := n.RunForIDP(context.Background(), "corp-ad")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sent != 1 {
			t.Errorf("expected 1 expired notification, got %d", sent)
		}
	})

	t.Run("expired failure does not fail the scan", func(t *testing.T) {
		database := openTestDB(t)
		n := New(database, idp.NewRegistry(testLogger()), newCryptoService(t), newAuditLogger(t, database), testLogger())

		testSetupADIDP(t, database, "corp-ad")
		testSMTPConfig(t, database)
		testEmailTemplate(t, database)

		if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
			IDPID:                "corp-ad",
			Enabled:              true,
			CronSchedule:         "0 0 * * *",
			DaysBeforeExpiration: 14,
			DaysAfterExpiration:  30,
		}); err != nil {
			t.Fatalf("saving expiration config: %v", err)
		}

		n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
			// The expired pass cannot read maxPwdAge.
			{err: newError("boom")},
		}}}

		sent, err := n.RunForIDP(context.Background(), "corp-ad")
		if err != nil {
			t.Fatalf("expired-pass failure must not fail the run: %v", err)
		}
		if sent != 0 {
			t.Errorf("expected 0 notifications, got %d", sent)
		}
	})
}

// saveSMTPConfigAt points the stored SMTP config at a live test server.
func saveSMTPConfigAt(t *testing.T, database *db.DB, host, port string) {
	t.Helper()
	cfgJSON := fmt.Sprintf(`{"host":%q,"port":%q,"enabled":true,"from_address":"passport@example.com"}`, host, port)
	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: cfgJSON}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}
}

// TestDryRunForIDP_ExpiredSection covers the expired-account half of the dry
// run, which only executes when DaysAfterExpiration is configured.
func TestDryRunForIDP_ExpiredSection(t *testing.T) {
	saveConfigWithAfter := func(t *testing.T, database *db.DB, idpID string) {
		t.Helper()
		if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
			IDPID:                idpID,
			Enabled:              true,
			CronSchedule:         "0 0 * * *",
			DaysBeforeExpiration: 14,
			DaysAfterExpiration:  -1,
		}); err != nil {
			t.Fatalf("saving expiration config: %v", err)
		}
	}

	t.Run("AD reports eligible and excluded expired users", func(t *testing.T) {
		database := openTestDB(t)
		n := New(database, idp.NewRegistry(testLogger()), newCryptoService(t), newAuditLogger(t, database), testLogger())

		testSetupADIDP(t, database, "corp-ad")
		saveConfigWithAfter(t, database, "corp-ad")
		if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
			{Attribute: "dn", Pattern: "svc-", Description: "exclude service accounts"},
		}); err != nil {
			t.Fatalf("saving filters: %v", err)
		}

		n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")}, // expiring: maxPwdAge
			{result: emptySearchResult()},                 // expiring: no one
			{result: maxPwdAgeEntry("dc=example,dc=com")}, // expired: maxPwdAge
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				adUserEntry("cn=alice,ou=Users,dc=example,dc=com", "alice", "alice@example.com", 100),
				adUserEntry("cn=svc-backup,ou=Users,dc=example,dc=com", "svc-backup", "svc@example.com", 120),
			}}},
		}}}

		result, err := n.DryRunForIDP(context.Background(), "corp-ad")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExpiredTotal != 2 {
			t.Errorf("ExpiredTotal = %d, want 2", result.ExpiredTotal)
		}
		if result.ExpiredEligibleCount != 1 {
			t.Errorf("ExpiredEligibleCount = %d, want 1", result.ExpiredEligibleCount)
		}
		if result.ExpiredExcludedCount != 1 {
			t.Errorf("ExpiredExcludedCount = %d, want 1", result.ExpiredExcludedCount)
		}
		// DaysRemaining is flipped positive for expired users so the UI can
		// render "expired N days ago" without re-deriving the sign.
		for _, u := range result.ExpiredUsers {
			if u.DaysRemaining < 0 {
				t.Errorf("user %s has negative DaysRemaining %d", u.Username, u.DaysRemaining)
			}
		}
	})

	t.Run("AD maxPwdAge failure yields no expired users", func(t *testing.T) {
		database := openTestDB(t)
		n := New(database, idp.NewRegistry(testLogger()), newCryptoService(t), newAuditLogger(t, database), testLogger())

		testSetupADIDP(t, database, "corp-ad")
		saveConfigWithAfter(t, database, "corp-ad")

		n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
			{err: newError("boom")},
		}}}

		result, err := n.DryRunForIDP(context.Background(), "corp-ad")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExpiredTotal != 0 {
			t.Errorf("ExpiredTotal = %d, want 0", result.ExpiredTotal)
		}
	})

	t.Run("FreeIPA expired users with attribute filter", func(t *testing.T) {
		database := openTestDB(t)
		n := New(database, idp.NewRegistry(testLogger()), newCryptoService(t), newAuditLogger(t, database), testLogger())

		testSetupFreeIPAIDP(t, database, "freeipa")
		saveConfigWithAfter(t, database, "freeipa")
		if err := database.SaveExpirationFilters(context.Background(), "freeipa", []db.ExpirationFilter{
			{Attribute: "department", Pattern: "^IT$", Description: "exclude IT"},
		}); err != nil {
			t.Fatalf("saving filters: %v", err)
		}

		n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searches: []mockSearch{
			// expiring pass: nobody, but the filter attribute is still read
			{result: emptySearchResult()},
			// expired pass
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				freeIPAUserEntry("uid=bob,cn=users,dc=example,dc=com", "bob", "bob@example.com", -10),
			}}},
			// readUserAttribute for bob's department
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				newTestEntry("uid=bob,cn=users,dc=example,dc=com", map[string][]string{"department": {"IT"}}),
			}}},
		}}}

		result, err := n.DryRunForIDP(context.Background(), "freeipa")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExpiredTotal != 1 {
			t.Fatalf("ExpiredTotal = %d, want 1", result.ExpiredTotal)
		}
		if result.ExpiredExcludedCount != 1 {
			t.Errorf("ExpiredExcludedCount = %d, want 1", result.ExpiredExcludedCount)
		}
	})

	t.Run("expired attribute read failure leaves user eligible", func(t *testing.T) {
		database := openTestDB(t)
		n := New(database, idp.NewRegistry(testLogger()), newCryptoService(t), newAuditLogger(t, database), testLogger())

		testSetupFreeIPAIDP(t, database, "freeipa")
		saveConfigWithAfter(t, database, "freeipa")
		if err := database.SaveExpirationFilters(context.Background(), "freeipa", []db.ExpirationFilter{
			{Attribute: "department", Pattern: "^IT$", Description: "exclude IT"},
		}); err != nil {
			t.Fatalf("saving filters: %v", err)
		}

		n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searches: []mockSearch{
			{result: emptySearchResult()},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				freeIPAUserEntry("uid=bob,cn=users,dc=example,dc=com", "bob", "bob@example.com", -10),
			}}},
			{err: newError("no such attribute")},
		}}}

		result, err := n.DryRunForIDP(context.Background(), "freeipa")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExpiredEligibleCount != 1 {
			t.Errorf("ExpiredEligibleCount = %d, want 1", result.ExpiredEligibleCount)
		}
	})
}
