package job

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// mockLDAPConn implements idp.LDAPConn for testing.
type mockLDAPConn struct {
	// searches is a queue of responses consumed in order; falls back to searchResult/searchErr.
	searches     []mockSearch
	searchResult *ldap.SearchResult
	searchErr    error
	bindErr      error
	closed       bool
}

type mockSearch struct {
	result *ldap.SearchResult
	err    error
}

func (m *mockLDAPConn) Bind(username, password string) error { return m.bindErr }
func (m *mockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if len(m.searches) > 0 {
		s := m.searches[0]
		m.searches = m.searches[1:]
		return s.result, s.err
	}
	return m.searchResult, m.searchErr
}
func (m *mockLDAPConn) Modify(req *ldap.ModifyRequest) error { return nil }
func (m *mockLDAPConn) PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	return nil, nil
}
func (m *mockLDAPConn) Close() error { m.closed = true; return nil }

// Compile-time check.
var _ idp.LDAPConn = (*mockLDAPConn)(nil)

// mockLDAPConnector implements idp.LDAPConnector for testing.
type mockLDAPConnector struct {
	conn    idp.LDAPConn
	connErr error
}

func (m *mockLDAPConnector) Connect(_ context.Context, _, _ string, _ int, _ bool) (idp.LDAPConn, error) {
	return m.conn, m.connErr
}

var _ idp.LDAPConnector = (*mockLDAPConnector)(nil)

// newTestEntry creates an ldap.Entry for a given DN using the map[string][]string API.
func newTestEntry(dn string, attrs map[string][]string) *ldap.Entry {
	return ldap.NewEntry(dn, attrs)
}

// --- parseWindowsFileTime ---

func TestParseWindowsFileTime_Valid(t *testing.T) {
	// Known Windows FILETIME for 2024-01-01 00:00:00 UTC
	// = (1704067200 + 11644473600) * 10,000,000 = 133485408000000000
	raw := "133485408000000000"
	got, err := parseWindowsFileTime(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.UTC().Equal(want) {
		t.Errorf("expected %v, got %v", want, got.UTC())
	}
}

func TestParseWindowsFileTime_Invalid(t *testing.T) {
	_, err := parseWindowsFileTime("not-a-number")
	if err == nil {
		t.Error("expected error for non-numeric input")
	}
}

func TestParseWindowsFileTime_Zero(t *testing.T) {
	_, err := parseWindowsFileTime("0")
	if err == nil {
		t.Error("expected error for zero filetime")
	}
}

func TestParseWindowsFileTime_Negative(t *testing.T) {
	_, err := parseWindowsFileTime("-1")
	if err == nil {
		t.Error("expected error for negative filetime")
	}
}

// --- parseGeneralizedTime ---

func TestParseGeneralizedTime_ZFormat(t *testing.T) {
	got, err := parseGeneralizedTime("20260415120000Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Year() != 2026 || got.Month() != 4 || got.Day() != 15 {
		t.Errorf("unexpected date: %v", got)
	}
}

func TestParseGeneralizedTime_PlusZeroFormat(t *testing.T) {
	got, err := parseGeneralizedTime("20260415120000+0000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Year() != 2026 {
		t.Errorf("unexpected year: %v", got.Year())
	}
}

func TestParseGeneralizedTime_MinusZeroFormat(t *testing.T) {
	got, err := parseGeneralizedTime("20260415120000-0000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Year() != 2026 {
		t.Errorf("unexpected year: %v", got.Year())
	}
}

func TestParseGeneralizedTime_Invalid(t *testing.T) {
	_, err := parseGeneralizedTime("not-a-date")
	if err == nil {
		t.Error("expected error for invalid date string")
	}
}

// --- getADMaxPwdAge ---

func TestGetADMaxPwdAge_Success(t *testing.T) {
	// maxPwdAge: -864000000000 = 10 days (positive in 100-ns intervals)
	// 10 days = 10 * 24 * 3600 * 1e7 = 8640000000000 hundred-nanoseconds
	entry := newTestEntry("dc=example,dc=com", map[string][]string{
		"maxPwdAge": {"-8640000000000"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}

	duration, err := getADMaxPwdAge(mock, "dc=example,dc=com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedDays := 10 * 24 * time.Hour
	if duration != expectedDays {
		t.Errorf("expected %v, got %v", expectedDays, duration)
	}
}

func TestGetADMaxPwdAge_SearchError(t *testing.T) {
	mock := &mockLDAPConn{searchErr: errors.New("LDAP error")}
	_, err := getADMaxPwdAge(mock, "dc=example,dc=com")
	if err == nil {
		t.Error("expected error from search failure")
	}
}

func TestGetADMaxPwdAge_NoEntries(t *testing.T) {
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	_, err := getADMaxPwdAge(mock, "dc=example,dc=com")
	if err == nil {
		t.Error("expected error when no entries returned")
	}
}

func TestGetADMaxPwdAge_MissingAttribute(t *testing.T) {
	entry := newTestEntry("dc=example,dc=com", map[string][]string{})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	_, err := getADMaxPwdAge(mock, "dc=example,dc=com")
	if err == nil {
		t.Error("expected error when maxPwdAge attribute is missing")
	}
}

func TestGetADMaxPwdAge_NonNegative(t *testing.T) {
	entry := newTestEntry("dc=example,dc=com", map[string][]string{
		"maxPwdAge": {"0"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	_, err := getADMaxPwdAge(mock, "dc=example,dc=com")
	if err == nil {
		t.Error("expected error for non-negative maxPwdAge")
	}
}

func TestGetADMaxPwdAge_InvalidValue(t *testing.T) {
	entry := newTestEntry("dc=example,dc=com", map[string][]string{
		"maxPwdAge": {"not-a-number"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	_, err := getADMaxPwdAge(mock, "dc=example,dc=com")
	if err == nil {
		t.Error("expected error for invalid maxPwdAge value")
	}
}

// --- searchADExpiringUsers ---

func TestSearchADExpiringUsers_Success(t *testing.T) {
	// Create a user whose password expires in 5 days from now.
	now := time.Now()
	expiresAt := now.Add(5 * 24 * time.Hour)
	maxPwdAge := 90 * 24 * time.Hour
	pwdLastSet := expiresAt.Add(-maxPwdAge)

	// Convert pwdLastSet to Windows FILETIME.
	const epochDiff = 11644473600
	secs := pwdLastSet.Unix() + epochDiff
	windowsFileTime := secs * 10000000

	entry := newTestEntry("CN=jdoe,DC=example,DC=com", map[string][]string{
		"sAMAccountName": {"jdoe"},
		"pwdLastSet":     {fmt.Sprintf("%d", windowsFileTime)},
		"mail":           {"jdoe@example.com"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}

	users, err := searchADExpiringUsers(mock, "dc=example,dc=com", "", "mail", maxPwdAge, 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "jdoe" {
		t.Errorf("expected jdoe, got %s", users[0].Username)
	}
	if users[0].Email != "jdoe@example.com" {
		t.Errorf("expected jdoe@example.com, got %s", users[0].Email)
	}
}

func TestSearchADExpiringUsers_NoResults(t *testing.T) {
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	users, err := searchADExpiringUsers(mock, "dc=example,dc=com", "", "mail", 90*24*time.Hour, 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}

func TestSearchADExpiringUsers_SearchError(t *testing.T) {
	mock := &mockLDAPConn{searchErr: errors.New("LDAP search failed")}
	_, err := searchADExpiringUsers(mock, "dc=example,dc=com", "", "mail", 90*24*time.Hour, 14)
	if err == nil {
		t.Error("expected error from search failure")
	}
}

func TestSearchADExpiringUsers_ZeroPwdLastSet(t *testing.T) {
	entry := newTestEntry("CN=jdoe,DC=example,DC=com", map[string][]string{
		"sAMAccountName": {"jdoe"},
		"pwdLastSet":     {"0"},
		"mail":           {"jdoe@example.com"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	users, err := searchADExpiringUsers(mock, "dc=example,dc=com", "", "mail", 90*24*time.Hour, 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users (skipped), got %d", len(users))
	}
}

func TestSearchADExpiringUsers_AlreadyExpired(t *testing.T) {
	const epochDiff = 11644473600
	pastExpiry := time.Now().Add(-2 * 24 * time.Hour)
	maxPwdAge := 90 * 24 * time.Hour
	pwdLastSet := pastExpiry.Add(-maxPwdAge)
	secs := pwdLastSet.Unix() + epochDiff
	windowsFileTime := secs * 10000000

	entry := newTestEntry("CN=jdoe,DC=example,DC=com", map[string][]string{
		"sAMAccountName": {"jdoe"},
		"pwdLastSet":     {fmt.Sprintf("%d", windowsFileTime)},
		"mail":           {"jdoe@example.com"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	users, err := searchADExpiringUsers(mock, "dc=example,dc=com", "", "mail", maxPwdAge, 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users (already expired), got %d", len(users))
	}
}

func TestSearchADExpiringUsers_CustomSearchBase(t *testing.T) {
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	_, err := searchADExpiringUsers(mock, "dc=example,dc=com", "ou=users,dc=example,dc=com", "mail", 90*24*time.Hour, 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- searchFreeIPAExpiringUsers ---

func TestSearchFreeIPAExpiringUsers_Success(t *testing.T) {
	expiresAt := time.Now().Add(5 * 24 * time.Hour).UTC()
	expStr := expiresAt.Format("20060102150405Z")

	entry := newTestEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"krbPasswordExpiration": {expStr},
		"mail":                  {"jdoe@example.com"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}

	users, err := searchFreeIPAExpiringUsers(mock, "dc=example,dc=com", "", "mail", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "jdoe" {
		t.Errorf("expected jdoe, got %s", users[0].Username)
	}
}

func TestSearchFreeIPAExpiringUsers_SearchError(t *testing.T) {
	mock := &mockLDAPConn{searchErr: errors.New("LDAP error")}
	_, err := searchFreeIPAExpiringUsers(mock, "dc=example,dc=com", "", "mail", 14)
	if err == nil {
		t.Error("expected error from search failure")
	}
}

func TestSearchFreeIPAExpiringUsers_EmptyExpiration(t *testing.T) {
	entry := newTestEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"krbPasswordExpiration": {""},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	users, err := searchFreeIPAExpiringUsers(mock, "dc=example,dc=com", "", "mail", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users (empty expiration skipped), got %d", len(users))
	}
}

func TestSearchFreeIPAExpiringUsers_AlreadyExpired(t *testing.T) {
	pastExpiry := time.Now().Add(-2 * 24 * time.Hour).UTC()
	expStr := pastExpiry.Format("20060102150405Z")

	entry := newTestEntry("uid=jdoe,cn=users,dc=example,dc=com", map[string][]string{
		"uid":                   {"jdoe"},
		"krbPasswordExpiration": {expStr},
		"mail":                  {"jdoe@example.com"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}
	users, err := searchFreeIPAExpiringUsers(mock, "dc=example,dc=com", "", "mail", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users (already expired), got %d", len(users))
	}
}

func TestSearchFreeIPAExpiringUsers_CustomSearchBase(t *testing.T) {
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	_, err := searchFreeIPAExpiringUsers(mock, "dc=example,dc=com", "cn=users,dc=example,dc=com", "mail", 14)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- readUserAttribute ---

func TestReadUserAttribute_Success(t *testing.T) {
	entry := newTestEntry("uid=jdoe,dc=example,dc=com", map[string][]string{
		"mail": {"jdoe@example.com"},
	})
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{Entries: []*ldap.Entry{entry}},
	}

	val, err := readUserAttribute(mock, "uid=jdoe,dc=example,dc=com", "mail")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "jdoe@example.com" {
		t.Errorf("expected jdoe@example.com, got %s", val)
	}
}

func TestReadUserAttribute_SearchError(t *testing.T) {
	mock := &mockLDAPConn{searchErr: errors.New("search failed")}
	_, err := readUserAttribute(mock, "uid=jdoe,dc=example,dc=com", "mail")
	if err == nil {
		t.Error("expected error from search failure")
	}
}

func TestReadUserAttribute_NotFound(t *testing.T) {
	mock := &mockLDAPConn{searchResult: &ldap.SearchResult{}}
	_, err := readUserAttribute(mock, "uid=notexist,dc=example,dc=com", "mail")
	if err == nil {
		t.Error("expected error when entry not found")
	}
}
