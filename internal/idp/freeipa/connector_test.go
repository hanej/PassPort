package freeipa

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// mockLDAPConn implements idp.LDAPConn for testing.
type mockLDAPConn struct {
	bindFunc           func(username, password string) error
	searchFunc         func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	modifyFunc         func(req *ldap.ModifyRequest) error
	passwordModifyFunc func(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	closed             bool
}

func (m *mockLDAPConn) Bind(username, password string) error {
	if m.bindFunc != nil {
		return m.bindFunc(username, password)
	}
	return nil
}

func (m *mockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.searchFunc != nil {
		return m.searchFunc(req)
	}
	return &ldap.SearchResult{}, nil
}

func (m *mockLDAPConn) Modify(req *ldap.ModifyRequest) error {
	if m.modifyFunc != nil {
		return m.modifyFunc(req)
	}
	return nil
}

func (m *mockLDAPConn) PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	if m.passwordModifyFunc != nil {
		return m.passwordModifyFunc(req)
	}
	return &ldap.PasswordModifyResult{}, nil
}

func (m *mockLDAPConn) Close() error {
	m.closed = true
	return nil
}

// mockLDAPConnector implements idp.LDAPConnector for testing.
type mockLDAPConnector struct {
	conn *mockLDAPConn
	err  error
}

func (m *mockLDAPConnector) Connect(_ context.Context, _, _ string, _ int, _ bool) (idp.LDAPConn, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.conn, nil
}

func newTestConnector(conn *mockLDAPConn) *Connector {
	cfg := idp.Config{
		Endpoint:        "ipa.example.com:636",
		Protocol:        "ldaps",
		BaseDN:          "dc=example,dc=com",
		UserSearchBase:  "cn=users,cn=accounts,dc=example,dc=com",
		GroupSearchBase: "cn=groups,cn=accounts,dc=example,dc=com",
		Timeout:         5,
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "uid=admin,cn=users,cn=accounts,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	connector := &mockLDAPConnector{conn: conn}
	logger := slog.Default()
	return New("test-ipa-1", cfg, secrets, connector, logger)
}

func TestTestConnection_Success(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("invalid credentials")
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.TestConnection(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !mock.closed {
		t.Error("expected connection to be closed")
	}
}

func TestTestConnection_Failure(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			return fmt.Errorf("bind failed: invalid credentials")
		},
	}
	c := newTestConnector(mock)

	err := c.TestConnection(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAuthenticate_Success(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username == "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com" && password == "user-pass" {
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
	}
	c := newTestConnector(mock)

	err := c.Authenticate(context.Background(), "jdoe", "user-pass")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestAuthenticate_Failure(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			return fmt.Errorf("invalid credentials")
		},
	}
	c := newTestConnector(mock)

	err := c.Authenticate(context.Background(), "jdoe", "wrong")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSearchUser_Found(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			return nil
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"},
				},
			}, nil
		},
	}
	c := newTestConnector(mock)

	dn, err := c.SearchUser(context.Background(), "uid", "jdoe")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if dn != "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com" {
		t.Errorf("unexpected DN: %q", dn)
	}
}

func TestSearchUser_NotFound(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			return nil
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c := newTestConnector(mock)

	_, err := c.SearchUser(context.Background(), "uid", "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

func TestConnectError(t *testing.T) {
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636",
		Protocol: "ldaps",
		BaseDN:   "dc=example,dc=com",
		Timeout:  5,
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "uid=admin,cn=users,cn=accounts,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	connector := &mockLDAPConnector{err: fmt.Errorf("connection refused")}
	c := New("test-ipa-err", cfg, secrets, connector, slog.Default())

	err := c.TestConnection(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestType(t *testing.T) {
	mock := &mockLDAPConn{}
	c := newTestConnector(mock)
	if c.Type() != idp.ProviderTypeFreeIPA {
		t.Errorf("expected type %q, got %q", idp.ProviderTypeFreeIPA, c.Type())
	}
}

func TestID(t *testing.T) {
	mock := &mockLDAPConn{}
	c := newTestConnector(mock)
	if c.ID() != "test-ipa-1" {
		t.Errorf("expected id %q, got %q", "test-ipa-1", c.ID())
	}
}

func TestChangePassword_Success(t *testing.T) {
	// ChangePassword flow:
	//   1. connect + Bind as user (verify old password)
	//   2. PasswordModify extended operation
	bindCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			bindCall++
			// User bind to verify old password
			expectedDN := "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"
			if username != expectedDN || password != "old-pass" {
				return fmt.Errorf("expected user bind %q/%q, got %q/%q", expectedDN, "old-pass", username, password)
			}
			return nil
		},
		passwordModifyFunc: func(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
			if req.UserIdentity != "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com" {
				return nil, fmt.Errorf("unexpected user identity: %s", req.UserIdentity)
			}
			return &ldap.PasswordModifyResult{}, nil
		},
	}
	c := newTestConnector(mock)

	err := c.ChangePassword(context.Background(), "jdoe", "old-pass", "new-pass")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if bindCall != 1 {
		t.Errorf("expected 1 bind call, got %d", bindCall)
	}
}

func TestResetPassword_Success(t *testing.T) {
	// ResetPassword flow:
	//   1. bindAsService (Connect + Bind as svc)
	//   2. PasswordModify extended operation
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		passwordModifyFunc: func(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
			expectedDN := "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"
			if req.UserIdentity != expectedDN {
				return nil, fmt.Errorf("unexpected user identity: %s", req.UserIdentity)
			}
			return &ldap.PasswordModifyResult{}, nil
		},
	}
	c := newTestConnector(mock)

	err := c.ResetPassword(context.Background(), "jdoe", "new-pass")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestUnlockAccount_Success(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			expectedDN := "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"
			if req.DN != expectedDN {
				return fmt.Errorf("unexpected modify DN: %s", req.DN)
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.UnlockAccount(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestEnableAccount_Success(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			expectedDN := "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"
			if req.DN != expectedDN {
				return fmt.Errorf("unexpected modify DN: %s", req.DN)
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.EnableAccount(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestGetUserGroups_Success(t *testing.T) {
	expectedGroups := []string{
		"cn=admins,cn=groups,cn=accounts,dc=example,dc=com",
		"cn=users,cn=groups,cn=accounts,dc=example,dc=com",
	}
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			// GetUserGroups searches for groups where member=userDN
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: expectedGroups[0]},
					{DN: expectedGroups[1]},
				},
			}, nil
		},
	}
	c := newTestConnector(mock)

	groups, err := c.GetUserGroups(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	for i, g := range groups {
		if g != expectedGroups[i] {
			t.Errorf("group[%d]: expected %q, got %q", i, expectedGroups[i], g)
		}
	}
}

func TestGetGroupMembers_Success(t *testing.T) {
	expectedMembers := []string{
		"uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
		"uid=jsmith,cn=users,cn=accounts,dc=example,dc=com",
	}
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			entry := ldap.NewEntry("cn=admins,cn=groups,cn=accounts,dc=example,dc=com", map[string][]string{
				"member": expectedMembers,
			})
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{entry},
			}, nil
		},
	}
	c := newTestConnector(mock)

	members, err := c.GetGroupMembers(context.Background(), "cn=admins,cn=groups,cn=accounts,dc=example,dc=com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
	for i, m := range members {
		if m != expectedMembers[i] {
			t.Errorf("member[%d]: expected %q, got %q", i, expectedMembers[i], m)
		}
	}
}

func TestGetUserAttribute_Success(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			entry := ldap.NewEntry("uid=jdoe,cn=users,cn=accounts,dc=example,dc=com", map[string][]string{
				"mail": {"jdoe@example.com"},
			})
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{entry},
			}, nil
		},
	}
	c := newTestConnector(mock)

	val, err := c.GetUserAttribute(context.Background(), "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com", "mail")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if val != "jdoe@example.com" {
		t.Errorf("expected %q, got %q", "jdoe@example.com", val)
	}
}

func TestEnableAccount_Error(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			return fmt.Errorf("insufficient access rights")
		},
	}
	c := newTestConnector(mock)

	err := c.EnableAccount(context.Background(), "jdoe")
	if err == nil {
		t.Fatal("expected error from Modify, got nil")
	}
}

func TestBuildUserDN_EmptySearchBase(t *testing.T) {
	// When UserSearchBase is empty, buildUserDN should fall back to BaseDN.
	cfg := idp.Config{
		Endpoint:        "ipa.example.com:636",
		Protocol:        "ldaps",
		BaseDN:          "dc=example,dc=com",
		UserSearchBase:  "", // intentionally empty
		GroupSearchBase: "",
		Timeout:         5,
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "uid=admin,cn=users,cn=accounts,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	connector := &mockLDAPConnector{conn: &mockLDAPConn{}}
	c := New("test-empty-base", cfg, secrets, connector, slog.Default())

	got := c.buildUserDN("jdoe")
	expected := "uid=jdoe,dc=example,dc=com"
	if got != expected {
		t.Errorf("buildUserDN with empty UserSearchBase = %q, want %q", got, expected)
	}
}

func TestGetGroupMembers_SearchError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, fmt.Errorf("LDAP server unavailable")
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetGroupMembers(context.Background(), "cn=admins,cn=groups,cn=accounts,dc=example,dc=com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetGroupMembers_NotFound(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetGroupMembers(context.Background(), "cn=admins,cn=groups,cn=accounts,dc=example,dc=com")
	if err == nil {
		t.Fatal("expected error for missing group, got nil")
	}
}

func TestGetUserAttribute_SearchError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, fmt.Errorf("LDAP server unavailable")
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetUserAttribute(context.Background(), "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com", "mail")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetUserAttribute_NotFound(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetUserAttribute(context.Background(), "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com", "mail")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

func TestGetUserGroups_SearchError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, fmt.Errorf("LDAP server unavailable")
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetUserGroups(context.Background(), "jdoe")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUnlockAccount_ModifyError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			return fmt.Errorf("constraint violation")
		},
	}
	c := newTestConnector(mock)

	err := c.UnlockAccount(context.Background(), "jdoe")
	if err == nil {
		t.Fatal("expected error from Modify, got nil")
	}
}

func TestSearchUser_MultipleMatches(t *testing.T) {
	// FreeIPA SearchUser uses SizeLimit=1 in the LDAP request, so the server
	// would normally enforce the limit. However, if the mock returns multiple
	// entries, the current code returns the first match without error.
	// This test documents that behavior.
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"},
					{DN: "uid=jdoe2,cn=users,cn=accounts,dc=example,dc=com"},
				},
			}, nil
		},
	}
	c := newTestConnector(mock)

	// Code returns the first entry since there is no explicit >1 check.
	dn, err := c.SearchUser(context.Background(), "uid", "jdoe")
	if err != nil {
		t.Fatalf("expected no error (current behavior), got: %v", err)
	}
	if dn != "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com" {
		t.Errorf("expected first entry DN, got %q", dn)
	}
}

func TestBuildUserDN(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		expected string
	}{
		{
			name:     "bare username",
			user:     "jdoe",
			expected: "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
		},
		{
			name:     "already a DN",
			user:     "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
			expected: "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
		},
		{
			name:     "custom DN with equals",
			user:     "cn=John Doe,ou=Special,dc=example,dc=com",
			expected: "cn=John Doe,ou=Special,dc=example,dc=com",
		},
	}

	mock := &mockLDAPConn{}
	c := newTestConnector(mock)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.buildUserDN(tt.user)
			if got != tt.expected {
				t.Errorf("buildUserDN(%q) = %q, want %q", tt.user, got, tt.expected)
			}
		})
	}
}

func TestAuthenticate_ConnectError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("connection refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636",
		Protocol: "ldaps",
		BaseDN:   "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	err := c.Authenticate(context.Background(), "jdoe", "pass")
	if err == nil {
		t.Fatal("expected connect error, got nil")
	}
}

func TestAuthenticate_BindError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			return fmt.Errorf("invalid credentials")
		},
	}
	c := newTestConnector(mock)
	err := c.Authenticate(context.Background(), "jdoe", "wrongpass")
	if err == nil {
		t.Fatal("expected bind error, got nil")
	}
}

func TestChangePassword_ConnectError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("connection refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636",
		Protocol: "ldaps",
		BaseDN:   "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	err := c.ChangePassword(context.Background(), "jdoe", "old", "new")
	if err == nil {
		t.Fatal("expected connect error, got nil")
	}
}

func TestChangePassword_BindError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			return fmt.Errorf("invalid credentials")
		},
	}
	c := newTestConnector(mock)
	err := c.ChangePassword(context.Background(), "jdoe", "wrongold", "new")
	if err == nil {
		t.Fatal("expected bind error, got nil")
	}
}

func TestChangePassword_PasswordModifyError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		passwordModifyFunc: func(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
			return nil, fmt.Errorf("password policy violation")
		},
	}
	c := newTestConnector(mock)
	err := c.ChangePassword(context.Background(), "jdoe", "old", "new")
	if err == nil {
		t.Fatal("expected PasswordModify error, got nil")
	}
}

func TestResetPassword_PasswordModifyError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" {
				return fmt.Errorf("unexpected bind for %q", username)
			}
			return nil
		},
		passwordModifyFunc: func(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
			return nil, fmt.Errorf("password too short")
		},
	}
	c := newTestConnector(mock)
	err := c.ResetPassword(context.Background(), "jdoe", "new")
	if err == nil {
		t.Fatal("expected PasswordModify error, got nil")
	}
}

func TestSearchUser_BindAsServiceError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("connection refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636",
		Protocol: "ldaps",
		BaseDN:   "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	_, err := c.SearchUser(context.Background(), "uid", "jdoe")
	if err == nil {
		t.Fatal("expected error from bindAsService, got nil")
	}
}

func TestSearchUser_SearchError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, fmt.Errorf("LDAP search failed")
		},
	}
	c := newTestConnector(mock)
	_, err := c.SearchUser(context.Background(), "uid", "jdoe")
	if err == nil {
		t.Fatal("expected search error, got nil")
	}
}

func TestSearchUser_NotFound_EmptyResult(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c := newTestConnector(mock)
	_, err := c.SearchUser(context.Background(), "mail", "nobody@example.com")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
}

// TestResetPassword_BindAsServiceError covers the bindAsService error in ResetPassword.
func TestResetPassword_BindAsServiceError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("service bind refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636", Protocol: "ldaps", BaseDN: "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	err := c.ResetPassword(context.Background(), "jdoe", "newpass")
	if err == nil {
		t.Fatal("expected error when bindAsService fails, got nil")
	}
}

// TestUnlockAccount_BindAsServiceError covers the bindAsService error in UnlockAccount.
func TestUnlockAccount_BindAsServiceError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("service bind refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636", Protocol: "ldaps", BaseDN: "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	err := c.UnlockAccount(context.Background(), "jdoe")
	if err == nil {
		t.Fatal("expected error when bindAsService fails, got nil")
	}
}

// TestEnableAccount_BindAsServiceError covers the bindAsService error in EnableAccount.
func TestEnableAccount_BindAsServiceError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("service bind refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636", Protocol: "ldaps", BaseDN: "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	err := c.EnableAccount(context.Background(), "jdoe")
	if err == nil {
		t.Fatal("expected error when bindAsService fails, got nil")
	}
}

// TestGetUserGroups_BindAsServiceError covers the bindAsService error in GetUserGroups.
func TestGetUserGroups_BindAsServiceError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("service bind refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636", Protocol: "ldaps", BaseDN: "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	_, err := c.GetUserGroups(context.Background(), "jdoe")
	if err == nil {
		t.Fatal("expected error when bindAsService fails, got nil")
	}
}

// TestGetUserGroups_EmptyGroupSearchBase covers the fallback to BaseDN when GroupSearchBase is empty.
func TestGetUserGroups_EmptyGroupSearchBase(t *testing.T) {
	entry := ldap.NewEntry("cn=admins,cn=groups,dc=example,dc=com", nil)
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	cfg := idp.Config{
		Endpoint:        "ipa.example.com:636",
		Protocol:        "ldaps",
		BaseDN:          "dc=example,dc=com",
		GroupSearchBase: "", // empty — should fall back to BaseDN
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "uid=admin,cn=users,cn=accounts,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	connector := &mockLDAPConnector{conn: mock}
	c := New("test-ipa", cfg, secrets, connector, slog.Default())

	groups, err := c.GetUserGroups(context.Background(), "jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}
}

// TestGetGroupMembers_BindAsServiceError covers the bindAsService error in GetGroupMembers.
func TestGetGroupMembers_BindAsServiceError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("service bind refused")}
	cfg := idp.Config{
		Endpoint: "ipa.example.com:636", Protocol: "ldaps", BaseDN: "dc=example,dc=com",
	}
	c := New("test-ipa", cfg, idp.Secrets{}, connector, slog.Default())
	_, err := c.GetGroupMembers(context.Background(), "cn=admins,dc=example,dc=com")
	if err == nil {
		t.Fatal("expected error when bindAsService fails, got nil")
	}
}
