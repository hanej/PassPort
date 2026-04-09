package job

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// testSetupADIDP creates an AD IDP record with a valid config.
func testSetupADIDP(t *testing.T, database *db.DB, idpID string) {
	t.Helper()
	cfg := idp.Config{
		Endpoint:       "ldap://localhost:389",
		Protocol:       "ldap",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           idpID,
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
	}); err != nil {
		t.Fatalf("creating AD IDP: %v", err)
	}
}

// testSetupFreeIPAIDP creates a FreeIPA IDP record.
func testSetupFreeIPAIDP(t *testing.T, database *db.DB, idpID string) {
	t.Helper()
	cfg := idp.Config{
		Endpoint:       "ldap://localhost:389",
		Protocol:       "ldap",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "cn=users,dc=example,dc=com",
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           idpID,
		FriendlyName: "FreeIPA",
		ProviderType: "freeipa",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
	}); err != nil {
		t.Fatalf("creating FreeIPA IDP: %v", err)
	}
}

// testEnabledExpirationConfig creates an enabled expiration config for an IDP.
func testEnabledExpirationConfig(t *testing.T, database *db.DB, idpID string) {
	t.Helper()
	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                idpID,
		Enabled:              true,
		CronSchedule:         "0 0 * * *",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}
}

// testSMTPConfig saves an enabled SMTP config.
func testSMTPConfig(t *testing.T, database *db.DB) {
	t.Helper()
	cfg := map[string]any{
		"host":    "smtp.example.com",
		"port":    "25",
		"enabled": true,
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}
}

// testEmailTemplate saves a password_expiration email template.
func testEmailTemplate(t *testing.T, database *db.DB) {
	t.Helper()
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "password_expiration",
		Subject:      "Password Expiring Soon for {{.Username}}",
		BodyHTML:     "<p>Hello {{.Username}}, your password expires on {{.ExpirationDate}}.</p>",
	}); err != nil {
		t.Fatalf("saving email template: %v", err)
	}
}

// maxPwdAgeEntry returns a mock LDAP search result for getADMaxPwdAge.
// Uses 90 days = -77760000000000 (100-nanosecond intervals, negative).
func maxPwdAgeEntry(baseDN string) *ldap.SearchResult {
	return &ldap.SearchResult{
		Entries: []*ldap.Entry{
			ldap.NewEntry(baseDN, map[string][]string{
				"maxPwdAge": {"-77760000000000"},
			}),
		},
	}
}

// emptySearchResult returns an LDAP result with no entries.
func emptySearchResult() *ldap.SearchResult {
	return &ldap.SearchResult{Entries: []*ldap.Entry{}}
}

// ---- RunForIDP with mock connector ----

func TestRunForIDP_ADSuccess_NoUsers(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")}, // getADMaxPwdAge
			{result: emptySearchResult()},                 // searchADExpiringUsers
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 notifications, got %d", count)
	}
}

func TestRunForIDP_FreeIPASuccess_NoUsers(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupFreeIPAIDP(t, database, "freeipa")
	testEnabledExpirationConfig(t, database, "freeipa")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	mockConn := &mockLDAPConn{searchResult: emptySearchResult()}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "freeipa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 notifications, got %d", count)
	}
}

func TestRunForIDP_ConnectFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	n.connector = &mockLDAPConnector{connErr: errLDAPConnFailed}

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when LDAP connect fails")
	}
}

func TestRunForIDP_BindFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	mockConn := &mockLDAPConn{bindErr: errLDAPBindFailed}
	n.connector = &mockLDAPConnector{conn: mockConn}

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when LDAP bind fails")
	}
}

func TestRunForIDP_ADMaxPwdAgeFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	// getADMaxPwdAge returns empty — no domain root
	mockConn := &mockLDAPConn{searchResult: emptySearchResult()}
	n.connector = &mockLDAPConnector{conn: mockConn}

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when maxPwdAge search returns no entries")
	}
}

func TestRunForIDP_NoEmailTemplate(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	// No email template saved.

	mockConn := &mockLDAPConn{searchResult: emptySearchResult()}
	n.connector = &mockLDAPConnector{conn: mockConn}

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when no email template found")
	}
}

// ---- DryRunForIDP with mock connector ----

func TestDryRunForIDP_ADSuccess_NoUsers(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalUsers != 0 {
		t.Errorf("expected 0 users, got %d", result.TotalUsers)
	}
}

func TestDryRunForIDP_FreeIPASuccess_NoUsers(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupFreeIPAIDP(t, database, "freeipa")
	testEnabledExpirationConfig(t, database, "freeipa")

	mockConn := &mockLDAPConn{searchResult: emptySearchResult()}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "freeipa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestDryRunForIDP_ConnectFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")

	n.connector = &mockLDAPConnector{connErr: errLDAPConnFailed}

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when LDAP connect fails")
	}
}

func TestDryRunForIDP_UnsupportedType(t *testing.T) {
	// The DB CHECK constraint prevents inserting unsupported provider types,
	// so this code path cannot be reached via normal DB operations.
	t.Skip("unsupported provider type cannot be inserted via DB due to CHECK constraint")
}

func TestDryRunForIDP_NoExpirationConfig_UsesDefaults(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	// IDP exists but no expiration config saved — should use defaults.
	testSetupADIDP(t, database, "corp-ad")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalUsers != 0 {
		t.Errorf("expected 0 users, got %d", result.TotalUsers)
	}
}

// sentinel errors for mock injection
var (
	errLDAPConnFailed = newError("mock: LDAP connection refused")
	errLDAPBindFailed = newError("mock: LDAP bind failed")
)

type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }

func newError(msg string) error { return &mockError{msg: msg} }

// windowsFileTimeFor returns the Windows FILETIME for (now - daysAgo days).
func windowsFileTimeFor(daysAgo int) string {
	ts := time.Now().Unix() - int64(daysAgo)*24*3600
	ft := (ts + 11644473600) * 10_000_000
	return strconv.FormatInt(ft, 10)
}

// adUserEntry returns a mock AD user LDAP entry expiring in ~(maxAgeDays - daysAgo) days.
func adUserEntry(dn, username, email string, daysAgo int) *ldap.Entry {
	attrs := map[string][]string{
		"sAMAccountName": {username},
		"pwdLastSet":     {windowsFileTimeFor(daysAgo)},
	}
	if email != "" {
		attrs["mail"] = []string{email}
	}
	return ldap.NewEntry(dn, attrs)
}

// freeIPAUserEntry returns a mock FreeIPA user entry expiring in daysFromNow days.
func freeIPAUserEntry(dn, username, email string, daysFromNow int) *ldap.Entry {
	expireTime := time.Now().Add(time.Duration(daysFromNow) * 24 * time.Hour)
	expStr := expireTime.UTC().Format("20060102150405Z")
	attrs := map[string][]string{
		"uid":                   {username},
		"krbPasswordExpiration": {expStr},
	}
	if email != "" {
		attrs["mail"] = []string{email}
	}
	return ldap.NewEntry(dn, attrs)
}

// ---- RunForIDP user-loop paths ----

func TestRunForIDP_ADWithUser_NoEmail(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	// User with no email — should be skipped.
	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sent (no email), got %d", count)
	}
}

func TestRunForIDP_ADWithUser_EmailSendFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database) // SMTP config points to smtp.example.com:25 which will fail
	testEmailTemplate(t, database)

	// User with email — send attempt will fail (no real SMTP), but RunForIDP continues.
	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	// Even though SendHTML fails, RunForIDP should not return an error — it logs and continues.
	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 0 sent because email failed
	if count != 0 {
		t.Errorf("expected 0 sent (SMTP failure), got %d", count)
	}
}

func TestRunForIDP_FreeIPAWithUser_NoEmail(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupFreeIPAIDP(t, database, "freeipa")
	testEnabledExpirationConfig(t, database, "freeipa")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	userEntry := freeIPAUserEntry("uid=jdoe,cn=users,dc=example,dc=com", "jdoe", "", 7)
	mockConn := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "freeipa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sent (no email), got %d", count)
	}
}

// ---- DryRunForIDP user-loop paths ----

func TestDryRunForIDP_ADWithUser(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalUsers != 1 {
		t.Errorf("expected 1 user, got %d", result.TotalUsers)
	}
	if result.EligibleCount != 1 {
		t.Errorf("expected 1 eligible, got %d", result.EligibleCount)
	}
}

func TestDryRunForIDP_ADWithUser_DNExclusionFilter(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	// Add an exclusion filter matching the user's DN.
	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "dn", Pattern: "jdoe", Description: "exclude jdoe"},
	}); err != nil {
		t.Fatalf("saving filters: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalUsers != 1 {
		t.Errorf("expected 1 user, got %d", result.TotalUsers)
	}
	if result.ExcludedCount != 1 {
		t.Errorf("expected 1 excluded, got %d", result.ExcludedCount)
	}
}

func TestDryRunForIDP_FreeIPAWithUser(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupFreeIPAIDP(t, database, "freeipa")
	testEnabledExpirationConfig(t, database, "freeipa")

	userEntry := freeIPAUserEntry("uid=jdoe,cn=users,dc=example,dc=com", "jdoe", "jdoe@example.com", 7)
	mockConn := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "freeipa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalUsers != 1 {
		t.Errorf("expected 1 user, got %d", result.TotalUsers)
	}
}

// ---- RunForIDP IDP-specific template path ----

func TestRunForIDP_IDPSpecificTemplate(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)

	// Save an IDP-specific template.
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "password_expiration:corp-ad",
		Subject:      "IDP-Specific: Password Expiring for {{.Username}}",
		BodyHTML:     "<p>Dear {{.Username}}, your password expires soon.</p>",
	}); err != nil {
		t.Fatalf("saving IDP-specific template: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// ---- RunForIDP exclusion filter paths ----

func TestRunForIDP_ADWithUser_DNExclusion(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "dn", Pattern: "jdoe", Description: "exclude jdoe"},
	}); err != nil {
		t.Fatalf("saving filters: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sent (user excluded), got %d", count)
	}
}

func TestRunForIDP_ADWithUser_AttrExclusionMatches(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	// Exclude users where "department" = "IT".
	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "department", Pattern: "^IT$", Description: "exclude IT dept"},
	}); err != nil {
		t.Fatalf("saving filters: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	// Third search will be readUserAttribute("department") → returns "IT".
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{"department": {"IT"}}),
			}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sent (user excluded by attr), got %d", count)
	}
}

func TestRunForIDP_ADWithUser_AttrExclusionReadFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	// Filter by attribute but the attribute read returns an error.
	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "department", Pattern: "^IT$"},
	}); err != nil {
		t.Fatalf("saving filters: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
			// Third search for readUserAttribute fails — filter continues.
			{err: newError("attribute read failed")},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	// Should not error; attribute read failure causes filter to be skipped.
	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDryRunForIDP_ADWithUser_AttrExclusion(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	// Exclude users in department "IT".
	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "department", Pattern: "^IT$", Description: "exclude IT"},
	}); err != nil {
		t.Fatalf("saving filters: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
			// readUserAttribute → returns "IT"
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{"department": {"IT"}}),
			}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExcludedCount != 1 {
		t.Errorf("expected 1 excluded, got %d", result.ExcludedCount)
	}
}

// ---- loadSchedules with invalid cron schedule ----

func TestLoadSchedules_InvalidCronSchedule(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	// Create IDP and enabled config with an invalid cron schedule.
	testCreateIDP(t, database, "corp-ad")
	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              true,
		CronSchedule:         "not-a-cron-schedule",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	// loadSchedules will log error for the invalid schedule — no panic expected.
	n.ReloadSchedules(context.Background())
}

// TestLoadSchedules_RemoveWhenDisabled covers the branch (lines 98-104) where an
// entry is removed because its IDP is no longer in the enabled configs.
func TestLoadSchedules_RemoveWhenDisabled(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	// Create IDP and enabled config.
	testCreateIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	// First reload — adds the schedule.
	n.ReloadSchedules(context.Background())

	// Now disable the config (set Enabled=false).
	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              false,
		CronSchedule:         "0 0 * * *",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("disabling expiration config: %v", err)
	}

	// Second reload — should remove the schedule for corp-ad.
	n.ReloadSchedules(context.Background())
}

// TestLoadSchedules_ReaddExistingEntry covers the branch (lines 108-112) where an
// existing entry is removed and re-added because its IDP is still enabled.
func TestLoadSchedules_ReaddExistingEntry(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	// Create IDP and enabled config.
	testCreateIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	// First reload — adds the schedule (entry goes into n.entries).
	n.ReloadSchedules(context.Background())

	// Second reload with the same config — since the entry exists, it will be
	// removed and re-added (exercises lines 108-112 in loadSchedules).
	n.ReloadSchedules(context.Background())
}

// TestRunForIDP_InvalidExclusionFilter covers the invalid regex warn-and-skip path.
func TestRunForIDP_InvalidExclusionFilter(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	// Save a filter with an invalid regex pattern.
	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "dn", Pattern: "[invalid-regex", Description: "bad filter"},
	}); err != nil {
		t.Fatalf("saving filter: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	// Should succeed (invalid filter is skipped with a warning).
	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Errorf("unexpected error (invalid filter should be skipped): %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 notifications, got %d", count)
	}
}

// TestRunForIDP_WithNotificationEmailAttr covers the emailAttr != "" branch.
func TestRunForIDP_WithNotificationEmailAttr(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	// Create IDP with NotificationEmailAttr set explicitly.
	cfg := idp.Config{
		Endpoint:              "ldap://localhost:389",
		Protocol:              "ldap",
		BaseDN:                "dc=example,dc=com",
		UserSearchBase:        "ou=Users,dc=example,dc=com",
		NotificationEmailAttr: "proxyAddresses",
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad-email",
		FriendlyName: "Corp AD Email",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	testEnabledExpirationConfig(t, database, "corp-ad-email")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "corp-ad-email")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 notifications, got %d", count)
	}
}

// TestDryRunForIDP_InvalidFilter covers the invalid exclusion filter skip path in DryRunForIDP.
func TestDryRunForIDP_InvalidFilter(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	// Invalid regex pattern.
	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "dn", Pattern: "[bad-regex", Description: "bad"},
	}); err != nil {
		t.Fatalf("saving filter: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// TestDryRunForIDP_FilterEmptyDescription covers the filter description fallback branch.
func TestDryRunForIDP_FilterEmptyDescription(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	// Filter with empty description — will hit the auto-description branch.
	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "dn", Pattern: "jdoe", Description: ""},
	}); err != nil {
		t.Fatalf("saving filter: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExcludedCount != 1 {
		t.Errorf("expected 1 excluded user, got %d", result.ExcludedCount)
	}
	// The auto-generated description should contain the attribute and pattern.
	if result.Users[0].FilterMatch == "" {
		t.Error("expected non-empty filter match description")
	}
}

// ---- Mock store for injecting DB errors into job package functions ----

// mockJobErrStore embeds *db.DB and selectively overrides methods to return errors.
type mockJobErrStore struct {
	*db.DB
	listEnabledExpirationConfigsErr error
	getIDPErr                       error
	listExpirationFiltersErr        error
}

func (m *mockJobErrStore) ListEnabledExpirationConfigs(ctx context.Context) ([]db.ExpirationConfig, error) {
	if m.listEnabledExpirationConfigsErr != nil {
		return nil, m.listEnabledExpirationConfigsErr
	}
	return m.DB.ListEnabledExpirationConfigs(ctx)
}

func (m *mockJobErrStore) GetIDP(ctx context.Context, id string) (*db.IdentityProviderRecord, error) {
	if m.getIDPErr != nil {
		return nil, m.getIDPErr
	}
	return m.DB.GetIDP(ctx, id)
}

func (m *mockJobErrStore) ListExpirationFilters(ctx context.Context, idpID string) ([]db.ExpirationFilter, error) {
	if m.listExpirationFiltersErr != nil {
		return nil, m.listExpirationFiltersErr
	}
	return m.DB.ListExpirationFilters(ctx, idpID)
}

// ---- loadSchedules error path ----

// TestLoadSchedules_ListEnabledError covers the ListEnabledExpirationConfigs error path
// in loadSchedules (line 87): the function should log the error and return silently.
func TestLoadSchedules_ListEnabledError(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)

	mock := &mockJobErrStore{
		DB:                              database,
		listEnabledExpirationConfigsErr: newError("DB read failed"),
	}
	n := New(mock, registry, cryptoSvc, al, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	// ReloadSchedules calls loadSchedules; the injected error should be logged and
	// return silently — no panic expected.
	n.ReloadSchedules(context.Background())
}

// ---- RunForIDP additional error paths ----

// TestRunForIDP_GetIDPError covers the GetIDP error branch (line 146).
func TestRunForIDP_GetIDPError(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)

	testCreateIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	mock := &mockJobErrStore{
		DB:        database,
		getIDPErr: newError("DB read failed"),
	}
	n := New(mock, registry, cryptoSvc, al, testLogger())

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when GetIDP fails")
	}
}

// TestRunForIDP_InvalidConfigJSON covers the json.Unmarshal ConfigJSON error (line 152).
func TestRunForIDP_InvalidConfigJSON(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "not-valid-json}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	testEnabledExpirationConfig(t, database, "corp-ad")

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error for invalid IDP ConfigJSON in RunForIDP")
	}
}

// TestRunForIDP_IDPDecryptSecretsError covers the IDP SecretBlob decrypt error (line 159).
func TestRunForIDP_IDPDecryptSecretsError(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := idp.Config{
		Endpoint: "ldap://localhost:389",
		Protocol: "ldap",
		BaseDN:   "dc=example,dc=com",
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
		SecretBlob:   []byte("this-is-not-valid-ciphertext"),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	testEnabledExpirationConfig(t, database, "corp-ad")

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when IDP SecretBlob cannot be decrypted")
	}
}

// TestRunForIDP_IDPSecretsInvalidJSON covers the json.Unmarshal IDP secrets error (line 162)
// where decryption succeeds but the plaintext is not valid JSON.
func TestRunForIDP_IDPSecretsInvalidJSON(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := idp.Config{
		Endpoint: "ldap://localhost:389",
		Protocol: "ldap",
		BaseDN:   "dc=example,dc=com",
	}
	cfgJSON, _ := json.Marshal(cfg)
	encrypted, encErr := cryptoSvc.Encrypt([]byte("not-valid-json"))
	if encErr != nil {
		t.Fatalf("encrypting: %v", encErr)
	}
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
		SecretBlob:   encrypted,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	testEnabledExpirationConfig(t, database, "corp-ad")

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when IDP secrets decrypt to invalid JSON")
	}
}

// TestRunForIDP_ListExpirationFiltersError covers the ListExpirationFilters error (line 192).
func TestRunForIDP_ListExpirationFiltersError(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	mock := &mockJobErrStore{
		DB:                       database,
		listExpirationFiltersErr: newError("DB read failed"),
	}
	n := New(mock, registry, cryptoSvc, al, testLogger())

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when ListExpirationFilters fails in RunForIDP")
	}
}

// TestRunForIDP_ADSearchFails covers the searchADExpiringUsers error (line 237)
// where maxPwdAge succeeds but the user search fails.
func TestRunForIDP_ADSearchFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{err: newError("LDAP user search failed")},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when AD user search fails")
	}
}

// TestRunForIDP_FreeIPASearchFails covers the searchFreeIPAExpiringUsers error (line 241).
func TestRunForIDP_FreeIPASearchFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupFreeIPAIDP(t, database, "freeipa")
	testEnabledExpirationConfig(t, database, "freeipa")
	testSMTPConfig(t, database)
	testEmailTemplate(t, database)

	n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searchErr: newError("LDAP search failed")}}

	_, err := n.RunForIDP(context.Background(), "freeipa")
	if err == nil {
		t.Error("expected error when FreeIPA user search fails")
	}
}

// TestRunForIDP_TemplateBadBody covers the body render error path (lines 295-297):
// when executeTemplate fails for the body, the user is skipped via continue.
func TestRunForIDP_TemplateBadBody(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)

	// Body has invalid template syntax — parse will fail.
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "password_expiration",
		Subject:      "Password Expiring for {{.Username}}",
		BodyHTML:     "{{.Unclosed",
	}); err != nil {
		t.Fatalf("saving email template: %v", err)
	}

	// User with email so we reach the template rendering code.
	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	// Body render failure logs a warning and continues — RunForIDP must not return an error.
	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sent (body render failed), got %d", count)
	}
}

// TestRunForIDP_TemplateBadSubject covers the subject render error path (lines 299-302):
// when the body renders successfully but the subject template is invalid.
func TestRunForIDP_TemplateBadSubject(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")
	testSMTPConfig(t, database)

	// Valid body, invalid subject — body renders OK then subject parse fails.
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "password_expiration",
		Subject:      "{{.Unclosed",
		BodyHTML:     "<p>Hello {{.Username}}, your password expires soon.</p>",
	}); err != nil {
		t.Fatalf("saving email template: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	count, err := n.RunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sent (subject render failed), got %d", count)
	}
}

// ---- DryRunForIDP additional error paths ----

// TestDryRunForIDP_BindFails covers the LDAP bind error path in DryRunForIDP (line 415).
func TestDryRunForIDP_BindFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	n.connector = &mockLDAPConnector{conn: &mockLDAPConn{bindErr: errLDAPBindFailed}}

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when LDAP bind fails in DryRunForIDP")
	}
}

// TestDryRunForIDP_IDPDecryptSecretsError covers the decrypt error in DryRunForIDP (line 376).
func TestDryRunForIDP_IDPDecryptSecretsError(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := idp.Config{
		Endpoint: "ldap://localhost:389",
		Protocol: "ldap",
		BaseDN:   "dc=example,dc=com",
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
		SecretBlob:   []byte("not-valid-ciphertext"),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when IDP SecretBlob cannot be decrypted in DryRunForIDP")
	}
}

// TestDryRunForIDP_IDPSecretsInvalidJSON covers the json.Unmarshal error for IDP secrets
// in DryRunForIDP (line 379): decryption succeeds but plaintext is not valid JSON.
func TestDryRunForIDP_IDPSecretsInvalidJSON(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := idp.Config{
		Endpoint: "ldap://localhost:389",
		Protocol: "ldap",
		BaseDN:   "dc=example,dc=com",
	}
	cfgJSON, _ := json.Marshal(cfg)
	encrypted, encErr := cryptoSvc.Encrypt([]byte("not-valid-json"))
	if encErr != nil {
		t.Fatalf("encrypting: %v", encErr)
	}
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(cfgJSON),
		SecretBlob:   encrypted,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when IDP secrets decrypt to invalid JSON in DryRunForIDP")
	}
}

// TestDryRunForIDP_ListExpirationFiltersError covers the ListExpirationFilters error
// in DryRunForIDP (line 385).
func TestDryRunForIDP_ListExpirationFiltersError(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)

	testSetupADIDP(t, database, "corp-ad")

	mock := &mockJobErrStore{
		DB:                       database,
		listExpirationFiltersErr: newError("DB read failed"),
	}
	n := New(mock, registry, cryptoSvc, al, testLogger())

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when ListExpirationFilters fails in DryRunForIDP")
	}
}

// TestDryRunForIDP_ADMaxPwdAgeFails covers the getADMaxPwdAge error path in DryRunForIDP (line 428).
func TestDryRunForIDP_ADMaxPwdAgeFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")

	// Empty result causes getADMaxPwdAge to fail.
	mockConn := &mockLDAPConn{searchResult: emptySearchResult()}
	n.connector = &mockLDAPConnector{conn: mockConn}

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when AD maxPwdAge search returns no entries in DryRunForIDP")
	}
}

// TestDryRunForIDP_ADSearchFails covers the searchADExpiringUsers error in DryRunForIDP (line 431)
// where maxPwdAge succeeds but the user search fails.
func TestDryRunForIDP_ADSearchFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{err: newError("LDAP user search failed")},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when AD user search fails in DryRunForIDP")
	}
}

// TestDryRunForIDP_FreeIPASearchFails covers the searchFreeIPAExpiringUsers error
// in DryRunForIDP (line 436).
func TestDryRunForIDP_FreeIPASearchFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupFreeIPAIDP(t, database, "freeipa")
	n.connector = &mockLDAPConnector{conn: &mockLDAPConn{searchErr: newError("LDAP search failed")}}

	_, err := n.DryRunForIDP(context.Background(), "freeipa")
	if err == nil {
		t.Error("expected error when FreeIPA user search fails in DryRunForIDP")
	}
}

// TestDryRunForIDP_AttrReadFails covers the readUserAttribute error path in DryRunForIDP's
// filter evaluation loop (line 468): when the attr read fails the filter is skipped and
// the user remains eligible.
func TestDryRunForIDP_AttrReadFails(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	testSetupADIDP(t, database, "corp-ad")
	testEnabledExpirationConfig(t, database, "corp-ad")

	if err := database.SaveExpirationFilters(context.Background(), "corp-ad", []db.ExpirationFilter{
		{Attribute: "department", Pattern: "^IT$"},
	}); err != nil {
		t.Fatalf("saving filter: %v", err)
	}

	userEntry := adUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "jdoe@example.com", 80)
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}},
			// readUserAttribute for "department" fails — filter is skipped.
			{err: newError("attribute read failed")},
		},
	}
	n.connector = &mockLDAPConnector{conn: mockConn}

	result, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Filter was skipped due to read error; user is not excluded.
	if result.EligibleCount != 1 {
		t.Errorf("expected 1 eligible user (filter skip on read error), got %d", result.EligibleCount)
	}
}

// ---- buildEmailConfig additional error path ----

// TestBuildEmailConfig_SecretsInvalidJSON covers the SMTP secrets json.Unmarshal error (line 521)
// where decryption succeeds but the plaintext is not valid JSON.
func TestBuildEmailConfig_SecretsInvalidJSON(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := map[string]any{
		"host":    "smtp.example.com",
		"port":    "587",
		"enabled": true,
	}
	cfgJSON, _ := json.Marshal(cfg)

	// Encrypt valid bytes that are not valid JSON so that decryption succeeds
	// but the subsequent json.Unmarshal of the plaintext fails.
	encrypted, encErr := cryptoSvc.Encrypt([]byte("not-valid-json"))
	if encErr != nil {
		t.Fatalf("encrypting: %v", encErr)
	}

	rec := &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
		SecretBlob: encrypted,
	}

	_, err := n.buildEmailConfig(rec)
	if err == nil {
		t.Error("expected error when SMTP secrets decrypt to invalid JSON")
	}
}
