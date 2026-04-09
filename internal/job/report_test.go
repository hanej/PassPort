package job

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

// ---- Test helpers ----

func testEnabledReportConfig(t *testing.T, database *db.DB, idpID, reportType string) {
	t.Helper()
	if err := database.SaveReportConfig(context.Background(), &db.ReportConfig{
		IDPID:                idpID,
		ReportType:           reportType,
		Enabled:              true,
		CronSchedule:         "0 7 * * 1",
		DaysBeforeExpiration: 14,
		Recipients:           "admin@example.com",
	}); err != nil {
		t.Fatalf("saving report config: %v", err)
	}
}

func testReportEmailTemplate(t *testing.T, database *db.DB, templateType string) {
	t.Helper()
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: templateType,
		Subject:      "Report: {{.ProviderName}}",
		BodyHTML:     "<p>Report on {{.GeneratedDate}}: {{.AccountCount}} accounts.</p>{{.ReportTable}}",
	}); err != nil {
		t.Fatalf("saving %s template: %v", templateType, err)
	}
}

// reportADUserEntry creates a mock AD LDAP entry for report tests.
// daysAgo: how many days ago pwdLastSet. With maxPwdAge=90d, user expires in (90-daysAgo) days.
// Use daysAgo=80 for a soon-to-expire user (10d remaining, within 14d threshold).
// Use daysAgo=100 for an expired user (expired 10d ago).
func reportADUserEntry(dn, username, displayName string, daysAgo int) *ldap.Entry {
	attrs := map[string][]string{
		"sAMAccountName": {username},
		"pwdLastSet":     {windowsFileTimeFor(daysAgo)},
	}
	if displayName != "" {
		attrs["displayName"] = []string{displayName}
	}
	return ldap.NewEntry(dn, attrs)
}

// reportADUserEntryWithLogon creates a mock AD entry with lastLogonTimestamp.
func reportADUserEntryWithLogon(dn, username string, daysAgo, logonDaysAgo int) *ldap.Entry {
	attrs := map[string][]string{
		"sAMAccountName":     {username},
		"pwdLastSet":         {windowsFileTimeFor(daysAgo)},
		"displayName":        {username + " Display"},
		"lastLogonTimestamp": {windowsFileTimeFor(logonDaysAgo)},
	}
	return ldap.NewEntry(dn, attrs)
}

// reportFreeIPAUserEntry creates a mock FreeIPA entry for report tests.
// daysFromNow: positive = expiring in future, negative = already expired.
func reportFreeIPAUserEntry(dn, username string, daysFromNow int) *ldap.Entry {
	expireTime := time.Now().Add(time.Duration(daysFromNow) * 24 * time.Hour)
	expStr := expireTime.UTC().Format("20060102150405Z")
	pwdChangeStr := time.Now().Add(-30 * 24 * time.Hour).UTC().Format("20060102150405Z")
	return ldap.NewEntry(dn, map[string][]string{
		"uid":                   {username},
		"cn":                    {username + " Full"},
		"krbPasswordExpiration": {expStr},
		"krbLastPwdChange":      {pwdChangeStr},
	})
}

// newReportScheduler creates a ReportScheduler for tests with a started cron scheduler.
// The scheduler is stopped when the context is cancelled.
func newReportScheduler(t *testing.T, database db.Store) *ReportScheduler {
	t.Helper()
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database.(*db.DB))
	rs := NewReportScheduler(database, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rs.Start(ctx)
	return rs
}

// ---- mockReportErrStore ----

type mockReportErrStore struct {
	*db.DB
	listEnabledReportConfigsErr error
	getIDPErr                   error
	getIDPResult                *db.IdentityProviderRecord // if non-nil, returned instead of DB lookup
	listReportFiltersErr        error
	getReportConfigErr          error
	getReportConfigResult       *db.ReportConfig // if non-nil, returned instead of DB lookup
	getEmailTemplateNil         bool             // when true, GetEmailTemplate returns nil, nil
}

func (m *mockReportErrStore) ListEnabledReportConfigs(ctx context.Context) ([]db.ReportConfig, error) {
	if m.listEnabledReportConfigsErr != nil {
		return nil, m.listEnabledReportConfigsErr
	}
	return m.DB.ListEnabledReportConfigs(ctx)
}

func (m *mockReportErrStore) GetIDP(ctx context.Context, id string) (*db.IdentityProviderRecord, error) {
	if m.getIDPErr != nil {
		return nil, m.getIDPErr
	}
	if m.getIDPResult != nil {
		return m.getIDPResult, nil
	}
	return m.DB.GetIDP(ctx, id)
}

func (m *mockReportErrStore) ListReportFilters(ctx context.Context, idpID, reportType string) ([]db.ReportFilter, error) {
	if m.listReportFiltersErr != nil {
		return nil, m.listReportFiltersErr
	}
	return m.DB.ListReportFilters(ctx, idpID, reportType)
}

func (m *mockReportErrStore) GetReportConfig(ctx context.Context, idpID, reportType string) (*db.ReportConfig, error) {
	if m.getReportConfigErr != nil {
		return nil, m.getReportConfigErr
	}
	if m.getReportConfigResult != nil {
		return m.getReportConfigResult, nil
	}
	return m.DB.GetReportConfig(ctx, idpID, reportType)
}

func (m *mockReportErrStore) GetEmailTemplate(ctx context.Context, templateType string) (*db.EmailTemplate, error) {
	if m.getEmailTemplateNil {
		return nil, nil
	}
	return m.DB.GetEmailTemplate(ctx, templateType)
}

// ---- NewReportScheduler / constructor ----

func TestNewReportScheduler(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)

	rs := NewReportScheduler(database, registry, cryptoSvc, al, testLogger())
	if rs == nil {
		t.Fatal("expected non-nil ReportScheduler")
	}
	if rs.connector == nil {
		t.Fatal("expected non-nil connector")
	}
}

// ---- parseRecipients ----

func TestParseRecipients_Empty(t *testing.T) {
	got := parseRecipients("")
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestParseRecipients_Single(t *testing.T) {
	got := parseRecipients("admin@example.com")
	if len(got) != 1 || got[0] != "admin@example.com" {
		t.Errorf("unexpected: %v", got)
	}
}

func TestParseRecipients_Multiple(t *testing.T) {
	got := parseRecipients("a@x.com, b@x.com, c@x.com")
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(got), got)
	}
	if got[0] != "a@x.com" || got[1] != "b@x.com" || got[2] != "c@x.com" {
		t.Errorf("unexpected: %v", got)
	}
}

func TestParseRecipients_Whitespace(t *testing.T) {
	got := parseRecipients("  a@x.com  ,  b@x.com  ")
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestParseRecipients_OnlyCommas(t *testing.T) {
	got := parseRecipients(",,,")
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

// ---- reportTemplateType ----

func TestReportTemplateType_Expired(t *testing.T) {
	got := reportTemplateType(db.ReportTypeExpired)
	if got != "expired_accounts_report" {
		t.Errorf("expected 'expired_accounts_report', got %q", got)
	}
}

func TestReportTemplateType_Expiration(t *testing.T) {
	got := reportTemplateType(db.ReportTypeExpiration)
	if got != "expiration_report" {
		t.Errorf("expected 'expiration_report', got %q", got)
	}
}

func TestReportTemplateType_Unknown(t *testing.T) {
	got := reportTemplateType("unknown")
	if got != "expiration_report" {
		t.Errorf("expected default 'expiration_report', got %q", got)
	}
}

// ---- renderReportTable ----

func TestRenderReportTable_Empty(t *testing.T) {
	html := renderReportTable(nil, false)
	if !strings.Contains(html, "<table") {
		t.Error("expected table tag in output")
	}
	if !strings.Contains(html, "<tbody>") {
		t.Error("expected tbody tag in output")
	}
}

func TestRenderReportTable_WithDaysRemaining(t *testing.T) {
	now := time.Now()
	users := []ReportUser{
		{
			DisplayName:     "John Doe",
			AccountName:     "jdoe",
			PasswordLastSet: now.Add(-30 * 24 * time.Hour),
			PasswordExpires: now.Add(7 * 24 * time.Hour),
			DaysRemaining:   7,
		},
	}
	html := renderReportTable(users, true)
	if !strings.Contains(html, "John Doe") {
		t.Error("expected display name in output")
	}
	if !strings.Contains(html, "Days Remaining") {
		t.Error("expected 'Days Remaining' column header")
	}
	if !strings.Contains(html, "7") {
		t.Error("expected days count in output")
	}
}

func TestRenderReportTable_NoDaysRemaining(t *testing.T) {
	now := time.Now()
	users := []ReportUser{
		{
			DisplayName:     "Jane Doe",
			AccountName:     "jdoe2",
			PasswordLastSet: now.Add(-100 * 24 * time.Hour),
			PasswordExpires: now.Add(-10 * 24 * time.Hour),
			DaysRemaining:   -10,
		},
	}
	html := renderReportTable(users, false)
	if strings.Contains(html, "Days Remaining") {
		t.Error("expected no 'Days Remaining' column for expired type")
	}
}

func TestRenderReportTable_WithLastLogon(t *testing.T) {
	now := time.Now()
	logon := now.Add(-5 * 24 * time.Hour)
	users := []ReportUser{
		{
			DisplayName:     "User One",
			AccountName:     "user1",
			PasswordLastSet: now.Add(-80 * 24 * time.Hour),
			PasswordExpires: now.Add(10 * 24 * time.Hour),
			DaysRemaining:   10,
			LastLogon:       &logon,
		},
	}
	html := renderReportTable(users, true)
	if !strings.Contains(html, "Last Logon") {
		t.Error("expected 'Last Logon' column when LastLogon is set")
	}
}

func TestRenderReportTable_LastLogonNil(t *testing.T) {
	// Mix of users with and without LastLogon — if any has it, column appears.
	now := time.Now()
	logon := now.Add(-3 * 24 * time.Hour)
	users := []ReportUser{
		{DisplayName: "A", AccountName: "a", PasswordLastSet: now, PasswordExpires: now.Add(7 * 24 * time.Hour)},
		{DisplayName: "B", AccountName: "b", PasswordLastSet: now, PasswordExpires: now.Add(7 * 24 * time.Hour), LastLogon: &logon},
	}
	html := renderReportTable(users, true)
	if !strings.Contains(html, "Last Logon") {
		t.Error("expected 'Last Logon' column because one user has it")
	}
}

func TestRenderReportTable_HTMLEscape(t *testing.T) {
	now := time.Now()
	users := []ReportUser{
		{
			DisplayName:     "<script>alert(1)</script>",
			AccountName:     "xss&user",
			PasswordLastSet: now,
			PasswordExpires: now.Add(7 * 24 * time.Hour),
		},
	}
	html := renderReportTable(users, false)
	if strings.Contains(html, "<script>") {
		t.Error("expected HTML escaping for display name")
	}
}

// ---- searchADReportUsers ----

func TestSearchADReportUsers_SoonToExpire(t *testing.T) {
	entry := reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "John Doe", 80)
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	maxPwdAge := 90 * 24 * time.Hour
	soon, expired, err := searchADReportUsers(mock, "dc=example,dc=com", "", maxPwdAge, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 1 {
		t.Errorf("expected 1 soon-to-expire user, got %d", len(soon))
	}
	if len(expired) != 0 {
		t.Errorf("expected 0 expired users, got %d", len(expired))
	}
	if soon[0].AccountName != "jdoe" {
		t.Errorf("unexpected account name: %s", soon[0].AccountName)
	}
	if soon[0].DisplayName != "John Doe" {
		t.Errorf("unexpected display name: %s", soon[0].DisplayName)
	}
}

func TestSearchADReportUsers_Expired(t *testing.T) {
	// 100 days ago with 90-day maxPwdAge = expired 10 days ago.
	entry := reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 100)
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 {
		t.Errorf("expected 0 soon-to-expire, got %d", len(soon))
	}
	if len(expired) != 1 {
		t.Errorf("expected 1 expired, got %d", len(expired))
	}
}

func TestSearchADReportUsers_ExcludeDisabled(t *testing.T) {
	// No entries returned (filter excludes disabled users).
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{},
	}
	soon, expired, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 || len(expired) != 0 {
		t.Errorf("expected empty results, got soon=%d expired=%d", len(soon), len(expired))
	}
}

func TestSearchADReportUsers_SearchError(t *testing.T) {
	mock := &mockLDAPConn{searchErr: errors.New("LDAP error")}
	_, _, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err == nil {
		t.Error("expected error from search failure")
	}
}

func TestSearchADReportUsers_ZeroPwdLastSet(t *testing.T) {
	entry := ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{
		"sAMAccountName": {"jdoe"},
		"pwdLastSet":     {"0"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 || len(expired) != 0 {
		t.Errorf("expected 0 users (pwdLastSet=0 skipped), got soon=%d expired=%d", len(soon), len(expired))
	}
}

func TestSearchADReportUsers_EmptyPwdLastSet(t *testing.T) {
	entry := ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{
		"sAMAccountName": {"jdoe"},
		"pwdLastSet":     {""},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 || len(expired) != 0 {
		t.Errorf("expected 0 users (empty pwdLastSet skipped)")
	}
}

func TestSearchADReportUsers_InvalidPwdLastSet(t *testing.T) {
	entry := ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{
		"sAMAccountName": {"jdoe"},
		"pwdLastSet":     {"not-a-number"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 || len(expired) != 0 {
		t.Errorf("expected 0 users (invalid pwdLastSet skipped)")
	}
}

func TestSearchADReportUsers_DisplayNameFallback(t *testing.T) {
	// No displayName → should fallback to givenName + sn.
	entry := ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{
		"sAMAccountName": {"jdoe"},
		"pwdLastSet":     {windowsFileTimeFor(80)}, // 90-80=10 days remaining
		"givenName":      {"John"},
		"sn":             {"Doe"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, _, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 1 {
		t.Fatalf("expected 1 user, got %d", len(soon))
	}
	if soon[0].DisplayName != "John Doe" {
		t.Errorf("expected 'John Doe', got %q", soon[0].DisplayName)
	}
}

func TestSearchADReportUsers_WithLastLogon(t *testing.T) {
	entry := reportADUserEntryWithLogon("cn=jdoe,dc=example,dc=com", "jdoe", 80, 5)
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, _, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 1 {
		t.Fatalf("expected 1 user, got %d", len(soon))
	}
	if soon[0].LastLogon == nil {
		t.Error("expected non-nil LastLogon")
	}
}

func TestSearchADReportUsers_CustomSearchBase(t *testing.T) {
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	_, _, err := searchADReportUsers(mock, "dc=example,dc=com", "ou=users,dc=example,dc=com", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSearchADReportUsers_EmptySearchBase(t *testing.T) {
	// Empty userSearchBase should default to baseDN.
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	_, _, err := searchADReportUsers(mock, "dc=example,dc=com", "", 90*24*time.Hour, 14, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- searchFreeIPAReportUsers ----

func TestSearchFreeIPAReportUsers_SoonToExpire(t *testing.T) {
	entry := reportFreeIPAUserEntry("uid=jdoe,cn=users,dc=example,dc=com", "jdoe", 7)
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 1 {
		t.Errorf("expected 1 soon-to-expire, got %d", len(soon))
	}
	if len(expired) != 0 {
		t.Errorf("expected 0 expired, got %d", len(expired))
	}
}

func TestSearchFreeIPAReportUsers_Expired(t *testing.T) {
	entry := reportFreeIPAUserEntry("uid=jdoe,cn=users,dc=example,dc=com", "jdoe", -10)
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 {
		t.Errorf("expected 0 soon-to-expire, got %d", len(soon))
	}
	if len(expired) != 1 {
		t.Errorf("expected 1 expired, got %d", len(expired))
	}
}

func TestSearchFreeIPAReportUsers_SearchError(t *testing.T) {
	mock := &mockLDAPConn{searchErr: errors.New("LDAP error")}
	_, _, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err == nil {
		t.Error("expected error from search failure")
	}
}

func TestSearchFreeIPAReportUsers_EmptyExpiration(t *testing.T) {
	entry := ldap.NewEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"krbPasswordExpiration": {""},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 || len(expired) != 0 {
		t.Errorf("expected 0 users (empty expiration skipped)")
	}
}

func TestSearchFreeIPAReportUsers_InvalidExpiration(t *testing.T) {
	entry := ldap.NewEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"krbPasswordExpiration": {"not-a-date"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, expired, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 0 || len(expired) != 0 {
		t.Errorf("expected 0 users (invalid expiration skipped)")
	}
}

func TestSearchFreeIPAReportUsers_WithLastLogon(t *testing.T) {
	expTime := time.Now().Add(7 * 24 * time.Hour).UTC()
	logonTime := time.Now().Add(-3 * 24 * time.Hour).UTC()
	entry := ldap.NewEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"cn":                    {"John Doe"},
		"krbPasswordExpiration": {expTime.Format("20060102150405Z")},
		"krbLastSuccessfulAuth": {logonTime.Format("20060102150405Z")},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, _, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 1 {
		t.Fatalf("expected 1 user, got %d", len(soon))
	}
	if soon[0].LastLogon == nil {
		t.Error("expected non-nil LastLogon")
	}
	if soon[0].DisplayName != "John Doe" {
		t.Errorf("unexpected display name: %s", soon[0].DisplayName)
	}
}

func TestSearchFreeIPAReportUsers_DisplayNameFallback(t *testing.T) {
	expTime := time.Now().Add(7 * 24 * time.Hour).UTC()
	entry := ldap.NewEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"givenName":             {"John"},
		"sn":                    {"Doe"},
		"krbPasswordExpiration": {expTime.Format("20060102150405Z")},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, _, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 1 {
		t.Fatalf("expected 1 user, got %d", len(soon))
	}
	if soon[0].DisplayName != "John Doe" {
		t.Errorf("expected 'John Doe', got %q", soon[0].DisplayName)
	}
}

func TestSearchFreeIPAReportUsers_krbLastPwdChange(t *testing.T) {
	expTime := time.Now().Add(7 * 24 * time.Hour).UTC()
	pwdChangeTime := time.Now().Add(-30 * 24 * time.Hour).UTC()
	entry := ldap.NewEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"krbPasswordExpiration": {expTime.Format("20060102150405Z")},
		"krbLastPwdChange":      {pwdChangeTime.Format("20060102150405Z")},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	soon, _, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(soon) != 1 {
		t.Fatalf("expected 1 user, got %d", len(soon))
	}
	if soon[0].PasswordLastSet.IsZero() {
		t.Error("expected non-zero PasswordLastSet from krbLastPwdChange")
	}
}

func TestSearchFreeIPAReportUsers_CustomSearchBase(t *testing.T) {
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	_, _, err := searchFreeIPAReportUsers(mock, "dc=example,dc=com", "cn=users,dc=example,dc=com", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- filterReportUsers ----

func TestFilterReportUsers_DNMatch_Excludes(t *testing.T) {
	re := regexp.MustCompile("^cn=svc")
	filters := []compiledReportFilter{
		{attribute: "dn", regex: re},
	}
	users := []ReportUser{
		{DN: "cn=svc-acct,dc=example,dc=com", AccountName: "svc"},
		{DN: "cn=jdoe,dc=example,dc=com", AccountName: "jdoe"},
	}
	mock := &mockLDAPConn{}
	result := filterReportUsers(mock, users, filters, testLogger())
	if len(result) != 1 {
		t.Fatalf("expected 1 user after filter, got %d", len(result))
	}
	if result[0].AccountName != "jdoe" {
		t.Errorf("expected jdoe, got %s", result[0].AccountName)
	}
}

func TestFilterReportUsers_DNNoMatch_Includes(t *testing.T) {
	re := regexp.MustCompile("^cn=NOMATCH")
	filters := []compiledReportFilter{
		{attribute: "dn", regex: re},
	}
	users := []ReportUser{
		{DN: "cn=jdoe,dc=example,dc=com", AccountName: "jdoe"},
	}
	mock := &mockLDAPConn{}
	result := filterReportUsers(mock, users, filters, testLogger())
	if len(result) != 1 {
		t.Errorf("expected 1 user, got %d", len(result))
	}
}

func TestFilterReportUsers_DistinguishedNameAttr(t *testing.T) {
	re := regexp.MustCompile("svc")
	filters := []compiledReportFilter{
		{attribute: "distinguishedName", regex: re},
	}
	users := []ReportUser{
		{DN: "cn=svc-acct,dc=example,dc=com", AccountName: "svc"},
	}
	mock := &mockLDAPConn{}
	result := filterReportUsers(mock, users, filters, testLogger())
	if len(result) != 0 {
		t.Errorf("expected 0 users after filter, got %d", len(result))
	}
}

func TestFilterReportUsers_AttributeFilter_Excludes(t *testing.T) {
	re := regexp.MustCompile("^TRUE$")
	filters := []compiledReportFilter{
		{attribute: "nsAccountLock", regex: re},
	}
	users := []ReportUser{
		{DN: "uid=locked,dc=example,dc=com", AccountName: "locked"},
	}
	// readUserAttribute will search for the user and return "TRUE".
	entry := ldap.NewEntry("uid=locked,dc=example,dc=com", map[string][]string{
		"nsAccountLock": {"TRUE"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	result := filterReportUsers(mock, users, filters, testLogger())
	if len(result) != 0 {
		t.Errorf("expected 0 users (locked account excluded), got %d", len(result))
	}
}

func TestFilterReportUsers_AttributeFilter_ReadError_Includes(t *testing.T) {
	re := regexp.MustCompile(".*")
	filters := []compiledReportFilter{
		{attribute: "nsAccountLock", regex: re},
	}
	users := []ReportUser{
		{DN: "uid=jdoe,dc=example,dc=com", AccountName: "jdoe"},
	}
	// Search returns error → readUserAttribute fails → continue, include user.
	mock := &mockLDAPConn{searchErr: errors.New("LDAP error")}
	result := filterReportUsers(mock, users, filters, testLogger())
	if len(result) != 1 {
		t.Errorf("expected 1 user (error reading attr → keep user), got %d", len(result))
	}
}

func TestFilterReportUsers_NoFilters(t *testing.T) {
	users := []ReportUser{
		{DN: "cn=jdoe,dc=example,dc=com", AccountName: "jdoe"},
		{DN: "cn=jane,dc=example,dc=com", AccountName: "jane"},
	}
	mock := &mockLDAPConn{}
	result := filterReportUsers(mock, users, nil, testLogger())
	if len(result) != 2 {
		t.Errorf("expected 2 users with no filters, got %d", len(result))
	}
}

// ---- RunReportForIDP ----

func TestRunReportForIDP_NoConfig(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")

	// No report config saved → GetReportConfig returns nil → error.
	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when no config found")
	}
}

func TestRunReportForIDP_GetReportConfigError(t *testing.T) {
	database := openTestDB(t)
	mock := &mockReportErrStore{DB: database, getReportConfigErr: newError("DB read failed")}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs.Start(ctx)

	testSetupADIDP(t, database, "corp-ad")

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when GetReportConfig fails")
	}
}

func TestRunReportForIDP_NoRecipients(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")

	// Save config with empty recipients.
	if err := database.SaveReportConfig(context.Background(), &db.ReportConfig{
		IDPID: "corp-ad", ReportType: db.ReportTypeExpiration,
		Enabled: true, CronSchedule: "0 7 * * 1", DaysBeforeExpiration: 14, Recipients: "",
	}); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error for empty recipients")
	}
}

func TestRunReportForIDP_ConnectFails(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)

	rs.connector = &mockLDAPConnector{connErr: errLDAPConnFailed}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when LDAP connect fails")
	}
}

func TestRunReportForIDP_BindFails(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)

	rs.connector = &mockLDAPConnector{conn: &mockLDAPConn{bindErr: errLDAPBindFailed}}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when bind fails")
	}
}

func TestRunReportForIDP_GetIDPError(t *testing.T) {
	database := openTestDB(t)
	mock := &mockReportErrStore{DB: database, getIDPErr: newError("IDP not found")}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs.Start(ctx)

	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when GetIDP fails")
	}
}

func TestRunReportForIDP_ListReportFiltersError(t *testing.T) {
	database := openTestDB(t)
	mock := &mockReportErrStore{DB: database, listReportFiltersErr: newError("DB read failed")}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs.Start(ctx)

	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	rs.connector = &mockLDAPConnector{connErr: errLDAPConnFailed}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	// ListReportFilters error propagates.
	if err == nil {
		t.Error("expected error from ListReportFilters or connect")
	}
}

func TestRunReportForIDP_InvalidConfigJSON(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)

	// Save IDP with invalid ConfigJSON.
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "bad-idp", FriendlyName: "Bad", ProviderType: "ad",
		Enabled: true, ConfigJSON: "not-json{",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	testEnabledReportConfig(t, database, "bad-idp", db.ReportTypeExpiration)

	err := rs.RunReportForIDP(context.Background(), "bad-idp", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error for invalid config JSON")
	}
}

func TestRunReportForIDP_ADMaxPwdAgeFails(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)

	// Return empty for maxPwdAge search (no domain root).
	rs.connector = &mockLDAPConnector{conn: &mockLDAPConn{searchResult: emptySearchResult()}}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when maxPwdAge search returns no entries")
	}
}

func TestRunReportForIDP_UnsupportedProvider(t *testing.T) {
	database := openTestDB(t)
	// Use a mock that returns an IDP with an unsupported provider type, bypassing
	// the DB CHECK constraint that only allows 'ad' and 'freeipa'.
	mock := &mockReportErrStore{
		DB: database,
		getIDPResult: &db.IdentityProviderRecord{
			ID:           "custom-idp",
			FriendlyName: "Custom",
			ProviderType: "custom",
			Enabled:      true,
			ConfigJSON:   `{"endpoint":"ldap://localhost:389","protocol":"ldap","base_dn":"dc=example,dc=com"}`,
		},
		getReportConfigResult: &db.ReportConfig{
			IDPID:                "custom-idp",
			ReportType:           db.ReportTypeExpiration,
			Enabled:              true,
			CronSchedule:         "0 7 * * 1",
			DaysBeforeExpiration: 14,
			Recipients:           "admin@example.com",
		},
	}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rs.Start(ctx)

	mockConn := &mockLDAPConn{}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "custom-idp", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error for unsupported provider type")
	}
}

func TestRunReportForIDP_UnknownReportType(t *testing.T) {
	database := openTestDB(t)
	testSetupADIDP(t, database, "corp-ad")
	// Use a mock that returns a config with an unknown report type, bypassing
	// the DB CHECK constraint that only allows 'expiration' and 'expired'.
	mock := &mockReportErrStore{
		DB: database,
		getReportConfigResult: &db.ReportConfig{
			IDPID:                "corp-ad",
			ReportType:           "unknown",
			Enabled:              true,
			CronSchedule:         "0 7 * * 1",
			DaysBeforeExpiration: 14,
			Recipients:           "admin@example.com",
		},
	}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rs.Start(ctx)

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", "unknown")
	if err == nil {
		t.Error("expected error for unknown report type")
	}
}

func TestRunReportForIDP_ADSuccess_NoUsers_Expiration(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	testSMTPConfig(t, database)
	testReportEmailTemplate(t, database, "expiration_report")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()}, // no users expiring
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReportForIDP_ADSuccess_NoUsers_Expired(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpired)
	testSMTPConfig(t, database)
	testReportEmailTemplate(t, database, "expired_accounts_report")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()}, // no expired users
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpired)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReportForIDP_FreeIPASuccess_NoUsers(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupFreeIPAIDP(t, database, "freeipa")
	testEnabledReportConfig(t, database, "freeipa", db.ReportTypeExpiration)
	testSMTPConfig(t, database)
	testReportEmailTemplate(t, database, "expiration_report")

	rs.connector = &mockLDAPConnector{conn: &mockLDAPConn{searchResult: emptySearchResult()}}

	err := rs.RunReportForIDP(context.Background(), "freeipa", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReportForIDP_NoSMTP(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	// No SMTP config saved.

	// Need users so we reach the SMTP check.
	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when SMTP is not configured")
	}
}

func TestRunReportForIDP_SMTPNotEnabled(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)

	// Save disabled SMTP config.
	smtpJSON, _ := json.Marshal(map[string]any{"host": "smtp.example.com", "port": "25", "enabled": false})
	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(smtpJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when SMTP is not enabled")
	}
}

func TestRunReportForIDP_InvalidSMTPJSON(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)

	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: "not-json{"}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error for invalid SMTP config JSON")
	}
}

func TestRunReportForIDP_NoEmailTemplate(t *testing.T) {
	database := openTestDB(t)
	// Use a mock store that returns nil for GetEmailTemplate so the
	// default seeded templates don't hide the "no template" error path.
	mock := &mockReportErrStore{DB: database, getEmailTemplateNil: true}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rs.Start(ctx)

	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	testSMTPConfig(t, database)
	// No email template — GetEmailTemplate returns nil via mock.

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when no email template found")
	}
}

func TestRunReportForIDP_ADWithUsers_EmailSilentFail(t *testing.T) {
	// Email send fails silently (SMTP host unreachable); function returns nil.
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	testSMTPConfig(t, database) // smtp.example.com:25 — unreachable, error logged as warning
	testReportEmailTemplate(t, database, "expiration_report")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "John Doe", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("expected nil (email failure logged as warning), got: %v", err)
	}
}

func TestRunReportForIDP_ADWithExpiredUsers(t *testing.T) {
	// Test the expired report type with AD users.
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpired)
	testSMTPConfig(t, database)
	testReportEmailTemplate(t, database, "expired_accounts_report")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 100), // expired 10 days ago
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpired)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReportForIDP_FreeIPAWithUsers(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupFreeIPAIDP(t, database, "freeipa")
	testEnabledReportConfig(t, database, "freeipa", db.ReportTypeExpiration)
	testSMTPConfig(t, database)
	testReportEmailTemplate(t, database, "expiration_report")

	rs.connector = &mockLDAPConnector{conn: &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{
			reportFreeIPAUserEntry("uid=jdoe,cn=users,dc=example,dc=com", "jdoe", 7),
		}},
	}}

	err := rs.RunReportForIDP(context.Background(), "freeipa", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReportForIDP_WithFilter_ExcludesUser(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	testSMTPConfig(t, database)
	testReportEmailTemplate(t, database, "expiration_report")

	// Save a filter that matches the user's DN.
	if err := database.SaveReportFilters(context.Background(), "corp-ad", db.ReportTypeExpiration, []db.ReportFilter{
		{IDPID: "corp-ad", ReportType: db.ReportTypeExpiration, Attribute: "dn", Pattern: "^cn=jdoe"},
	}); err != nil {
		t.Fatalf("saving filters: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	// User filtered out → 0 users → no email sent → nil error.
	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReportForIDP_IDPSpecificTemplate(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	testSMTPConfig(t, database)

	// Save an IDP-specific template.
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "expiration_report:corp-ad",
		Subject:      "Custom Report for corp-ad",
		BodyHTML:     "<p>Custom template. Accounts: {{.AccountCount}}</p>{{.ReportTable}}",
	}); err != nil {
		t.Fatalf("saving IDP-specific template: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error with IDP-specific template: %v", err)
	}
}

func TestRunReportForIDP_InvalidBodyTemplate(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	testSMTPConfig(t, database)

	// Template with invalid syntax.
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "expiration_report",
		Subject:      "Report",
		BodyHTML:     "{{.Unclosed",
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error for invalid body template syntax")
	}
}

func TestRunReportForIDP_InvalidSubjectTemplate(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	testSMTPConfig(t, database)

	// Valid body, invalid subject.
	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "expiration_report",
		Subject:      "{{.Unclosed",
		BodyHTML:     "<p>Report {{.AccountCount}}</p>{{.ReportTable}}",
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	err := rs.RunReportForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error for invalid subject template syntax")
	}
}

// ---- PreviewForIDP ----

func TestPreviewForIDP_NoIDP(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)

	// No IDP in DB — gatherUsers errors out.
	_, err := rs.PreviewForIDP(context.Background(), "nonexistent", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error for nonexistent IDP")
	}
}

func TestPreviewForIDP_ConnectFails(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")

	rs.connector = &mockLDAPConnector{connErr: errLDAPConnFailed}

	_, err := rs.PreviewForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when connect fails")
	}
}

func TestPreviewForIDP_NoTemplate(t *testing.T) {
	database := openTestDB(t)
	// Use a mock store that returns nil for GetEmailTemplate so the
	// default seeded templates don't hide the "no template" error path.
	mock := &mockReportErrStore{DB: database, getEmailTemplateNil: true}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rs.Start(ctx)

	testSetupADIDP(t, database, "corp-ad")
	// No email template — GetEmailTemplate returns nil via mock.

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	_, err := rs.PreviewForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when no email template exists")
	}
}

func TestPreviewForIDP_ADSuccess_NoUsers(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testReportEmailTemplate(t, database, "expiration_report")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	result, err := rs.PreviewForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Count != 0 {
		t.Errorf("expected count=0, got %d", result.Count)
	}
	if !strings.Contains(result.HTML, "<table") {
		t.Error("expected HTML table in result")
	}
}

func TestPreviewForIDP_ADSuccess_WithUsers(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testReportEmailTemplate(t, database, "expiration_report")

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: &ldap.SearchResult{Entries: []*ldap.Entry{
				reportADUserEntry("cn=jdoe,dc=example,dc=com", "jdoe", "John Doe", 80),
			}}},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	result, err := rs.PreviewForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Count != 1 {
		t.Errorf("expected count=1, got %d", result.Count)
	}
}

func TestPreviewForIDP_FreeIPASuccess_NoUsers(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupFreeIPAIDP(t, database, "freeipa")
	testReportEmailTemplate(t, database, "expired_accounts_report")

	rs.connector = &mockLDAPConnector{conn: &mockLDAPConn{searchResult: emptySearchResult()}}

	result, err := rs.PreviewForIDP(context.Background(), "freeipa", db.ReportTypeExpired)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Count != 0 {
		t.Errorf("expected count=0, got %d", result.Count)
	}
}

func TestPreviewForIDP_UsesDBConfig(t *testing.T) {
	// When config exists in DB, it should be used (instead of defaults).
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")
	testReportEmailTemplate(t, database, "expiration_report")

	// Save a config with 30-day threshold.
	if err := database.SaveReportConfig(context.Background(), &db.ReportConfig{
		IDPID: "corp-ad", ReportType: db.ReportTypeExpiration,
		Enabled: true, CronSchedule: "0 7 * * 1", DaysBeforeExpiration: 30,
	}); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	mockConn := &mockLDAPConn{
		searches: []mockSearch{
			{result: maxPwdAgeEntry("dc=example,dc=com")},
			{result: emptySearchResult()},
		},
	}
	rs.connector = &mockLDAPConnector{conn: mockConn}

	result, err := rs.PreviewForIDP(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ---- loadSchedules ----

func TestLoadSchedules_ListEnabledError_Silent(t *testing.T) {
	database := openTestDB(t)
	mock := &mockReportErrStore{
		DB:                          database,
		listEnabledReportConfigsErr: newError("DB read failed"),
	}
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	rs := NewReportScheduler(mock, registry, cryptoSvc, al, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rs.Start(ctx)

	// Error is logged and silently skipped; no panic expected.
	rs.ReloadSchedules(context.Background())
}

func TestLoadSchedules_AddAndRemoveCycle(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")

	// Add an enabled config → loadSchedules should add it.
	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	rs.ReloadSchedules(context.Background())

	rs.mu.Lock()
	entriesAfterAdd := len(rs.entries)
	rs.mu.Unlock()
	if entriesAfterAdd != 1 {
		t.Errorf("expected 1 cron entry after add, got %d", entriesAfterAdd)
	}

	// Disable the config → loadSchedules should remove it.
	if err := database.SaveReportConfig(context.Background(), &db.ReportConfig{
		IDPID: "corp-ad", ReportType: db.ReportTypeExpiration,
		Enabled: false, CronSchedule: "0 7 * * 1",
	}); err != nil {
		t.Fatalf("disabling config: %v", err)
	}
	rs.ReloadSchedules(context.Background())

	rs.mu.Lock()
	entriesAfterRemove := len(rs.entries)
	rs.mu.Unlock()
	if entriesAfterRemove != 0 {
		t.Errorf("expected 0 cron entries after disable, got %d", entriesAfterRemove)
	}
}

func TestLoadSchedules_UpdatedSchedule(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")

	testEnabledReportConfig(t, database, "corp-ad", db.ReportTypeExpiration)
	rs.ReloadSchedules(context.Background())

	// Capture the old entry ID.
	rs.mu.Lock()
	oldID := rs.entries["corp-ad:"+db.ReportTypeExpiration]
	rs.mu.Unlock()

	// Update the schedule.
	if err := database.SaveReportConfig(context.Background(), &db.ReportConfig{
		IDPID: "corp-ad", ReportType: db.ReportTypeExpiration,
		Enabled: true, CronSchedule: "0 8 * * 1",
	}); err != nil {
		t.Fatalf("updating config: %v", err)
	}
	rs.ReloadSchedules(context.Background())

	rs.mu.Lock()
	newID := rs.entries["corp-ad:"+db.ReportTypeExpiration]
	rs.mu.Unlock()

	// Entry should have been replaced (new entry ID).
	if oldID == newID {
		t.Error("expected new cron entry ID after schedule update")
	}
}

func TestLoadSchedules_InvalidCron_Skips(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)
	testSetupADIDP(t, database, "corp-ad")

	// Save config with invalid cron expression.
	if err := database.SaveReportConfig(context.Background(), &db.ReportConfig{
		IDPID: "corp-ad", ReportType: db.ReportTypeExpiration,
		Enabled: true, CronSchedule: "not-a-cron !",
	}); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	// Should not panic, just log error and skip.
	rs.ReloadSchedules(context.Background())

	rs.mu.Lock()
	entries := len(rs.entries)
	rs.mu.Unlock()
	if entries != 0 {
		t.Errorf("expected 0 entries for invalid cron, got %d", entries)
	}
}

func TestRunReportForIDP_DecryptSecretsError(t *testing.T) {
	database := openTestDB(t)
	rs := newReportScheduler(t, database)

	// Create IDP with invalid (corrupt) SecretBlob so Decrypt fails.
	cfg := map[string]any{
		"endpoint": "ldap://localhost:389",
		"protocol": "ldap",
		"base_dn":  "dc=example,dc=com",
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-bad-secret", FriendlyName: "Corp Bad", ProviderType: "ad",
		Enabled:    true,
		ConfigJSON: string(cfgJSON),
		SecretBlob: []byte("not-valid-ciphertext"),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
	testEnabledReportConfig(t, database, "corp-bad-secret", db.ReportTypeExpiration)

	err := rs.RunReportForIDP(context.Background(), "corp-bad-secret", db.ReportTypeExpiration)
	if err == nil {
		t.Error("expected error when decrypting secrets fails")
	}
}
