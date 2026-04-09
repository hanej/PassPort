package ad

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
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
		Timeout:        5,
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	connector := &mockLDAPConnector{conn: conn}
	logger := slog.Default()
	return New("test-ad-1", cfg, secrets, connector, logger)
}

func TestTestConnection_Success(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "cn=admin,dc=example,dc=com" || password != "admin-secret" {
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
	// Authenticate with a UPN (user@domain) calls resolveUserDN which:
	//   1. Strips domain -> "jdoe"
	//   2. Calls SearchUser -> bindAsService (Connect + Bind as svc) + Search
	// Then Authenticate does:
	//   3. connect (returns same mock conn)
	//   4. Bind as user DN returned by search
	bindCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			bindCall++
			switch bindCall {
			case 1:
				// Service account bind for resolveUserDN -> SearchUser -> bindAsService
				if username != "cn=admin,dc=example,dc=com" || password != "admin-secret" {
					return fmt.Errorf("expected service account bind, got %q / %q", username, password)
				}
				return nil
			case 2:
				// User bind for authentication
				if username != "cn=John Doe,ou=Users,dc=example,dc=com" || password != "user-pass" {
					return fmt.Errorf("expected user bind, got %q / %q", username, password)
				}
				return nil
			default:
				return fmt.Errorf("unexpected bind call %d", bindCall)
			}
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
	}
	c := newTestConnector(mock)

	err := c.Authenticate(context.Background(), "jdoe@example.com", "user-pass")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if bindCall != 2 {
		t.Errorf("expected 2 bind calls, got %d", bindCall)
	}
}

func TestAuthenticate_Failure(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			return fmt.Errorf("invalid credentials")
		},
	}
	c := newTestConnector(mock)

	err := c.Authenticate(context.Background(), "jdoe@example.com", "wrong")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSearchUser_Found(t *testing.T) {
	bindCount := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			bindCount++
			return nil
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
	}
	c := newTestConnector(mock)

	dn, err := c.SearchUser(context.Background(), "sAMAccountName", "jdoe")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if dn != "cn=John Doe,ou=Users,dc=example,dc=com" {
		t.Errorf("expected DN 'cn=John Doe,ou=Users,dc=example,dc=com', got %q", dn)
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

	_, err := c.SearchUser(context.Background(), "sAMAccountName", "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

func TestConnectError(t *testing.T) {
	cfg := idp.Config{
		Endpoint: "dc.example.com:636",
		Protocol: "ldaps",
		BaseDN:   "dc=example,dc=com",
		Timeout:  5,
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	connector := &mockLDAPConnector{err: fmt.Errorf("connection refused")}
	c := New("test-ad-err", cfg, secrets, connector, slog.Default())

	err := c.TestConnection(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestType(t *testing.T) {
	mock := &mockLDAPConn{}
	c := newTestConnector(mock)
	if c.Type() != idp.ProviderTypeAD {
		t.Errorf("expected type %q, got %q", idp.ProviderTypeAD, c.Type())
	}
}

func TestID(t *testing.T) {
	mock := &mockLDAPConn{}
	c := newTestConnector(mock)
	if c.ID() != "test-ad-1" {
		t.Errorf("expected id %q, got %q", "test-ad-1", c.ID())
	}
}

func TestAuthenticate_WithDN(t *testing.T) {
	// When the user input contains "=", resolveUserDN returns it as-is
	// and no service bind / search is performed.
	bindCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			bindCall++
			// Only call should be the user bind with the supplied DN.
			if username != "cn=John Doe,ou=Users,dc=example,dc=com" || password != "secret" {
				return fmt.Errorf("unexpected bind: %q / %q", username, password)
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.Authenticate(context.Background(), "cn=John Doe,ou=Users,dc=example,dc=com", "secret")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if bindCall != 1 {
		t.Errorf("expected 1 bind call (user only), got %d", bindCall)
	}
}

func TestAuthenticate_UserNotFound(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil }, // svc bind succeeds
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c := newTestConnector(mock)

	err := c.Authenticate(context.Background(), "nobody@example.com", "pass")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

func TestChangePassword_Success(t *testing.T) {
	// ChangePassword flow:
	//   1. resolveUserDN -> bindAsService + Search (user has "@" so strips domain)
	//   2. connect + Bind as user (with resolved DN)
	//   3. Modify with Delete+Add on unicodePwd (while bound as user)
	bindCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			bindCall++
			switch bindCall {
			case 1:
				// Service account bind inside resolveUserDN
				if username != "cn=admin,dc=example,dc=com" || password != "admin-secret" {
					return fmt.Errorf("expected svc bind, got %q / %q", username, password)
				}
			case 2:
				// User bind with resolved DN for password change
				if username != "cn=John Doe,ou=Users,dc=example,dc=com" || password != "old-pass" {
					return fmt.Errorf("expected user bind, got %q / %q", username, password)
				}
			default:
				return fmt.Errorf("unexpected bind call %d", bindCall)
			}
			return nil
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			if req.DN != "cn=John Doe,ou=Users,dc=example,dc=com" {
				return fmt.Errorf("unexpected modify DN: %s", req.DN)
			}
			// Must be Delete+Add (user self-change), not Replace (admin op).
			if len(req.Changes) != 2 {
				return fmt.Errorf("expected 2 changes (Delete+Add), got %d", len(req.Changes))
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.ChangePassword(context.Background(), "jdoe@example.com", "old-pass", "new-pass")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if bindCall != 2 {
		t.Fatalf("expected 2 bind calls, got %d", bindCall)
	}
}

func TestResetPassword_Success(t *testing.T) {
	// ResetPassword flow:
	//   1. resolveUserDN -> bindAsService + Search
	//   2. bindAsService + Modify
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "cn=admin,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			if req.DN != "cn=John Doe,ou=Users,dc=example,dc=com" {
				return fmt.Errorf("unexpected modify DN: %s", req.DN)
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.ResetPassword(context.Background(), "jdoe@example.com", "new-pass")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestUnlockAccount_Success(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "cn=admin,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			if req.DN != "cn=John Doe,ou=Users,dc=example,dc=com" {
				return fmt.Errorf("unexpected modify DN: %s", req.DN)
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.UnlockAccount(context.Background(), "jdoe@example.com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestGetUserGroups_Success(t *testing.T) {
	expectedGroups := []string{
		"cn=Admins,ou=Groups,dc=example,dc=com",
		"cn=Users,ou=Groups,dc=example,dc=com",
	}
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				// resolveUserDN search
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			// GetUserGroups search - return memberOf values
			entry := ldap.NewEntry("cn=John Doe,ou=Users,dc=example,dc=com", map[string][]string{
				"memberOf": expectedGroups,
			})
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{entry},
			}, nil
		},
	}
	c := newTestConnector(mock)

	groups, err := c.GetUserGroups(context.Background(), "jdoe@example.com")
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
		"cn=John Doe,ou=Users,dc=example,dc=com",
		"cn=Jane Doe,ou=Users,dc=example,dc=com",
	}
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			entry := ldap.NewEntry("cn=Admins,ou=Groups,dc=example,dc=com", map[string][]string{
				"member": expectedMembers,
			})
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{entry},
			}, nil
		},
	}
	c := newTestConnector(mock)

	members, err := c.GetGroupMembers(context.Background(), "cn=Admins,ou=Groups,dc=example,dc=com")
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
			entry := ldap.NewEntry("cn=John Doe,ou=Users,dc=example,dc=com", map[string][]string{
				"mail": {"jdoe@example.com"},
			})
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{entry},
			}, nil
		},
	}
	c := newTestConnector(mock)

	val, err := c.GetUserAttribute(context.Background(), "cn=John Doe,ou=Users,dc=example,dc=com", "mail")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if val != "jdoe@example.com" {
		t.Errorf("expected %q, got %q", "jdoe@example.com", val)
	}
}

func TestResolveUserDN_AlreadyDN(t *testing.T) {
	// If input contains "=", resolveUserDN returns it as-is without any LDAP calls.
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			t.Error("bind should not be called for DN input")
			return nil
		},
		searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
			t.Error("search should not be called for DN input")
			return nil, nil
		},
	}
	c := newTestConnector(mock)

	dn, err := c.resolveUserDN(context.Background(), "cn=John Doe,ou=Users,dc=example,dc=com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if dn != "cn=John Doe,ou=Users,dc=example,dc=com" {
		t.Errorf("expected DN unchanged, got %q", dn)
	}
}

func TestResolveUserDN_StripsDomain(t *testing.T) {
	// "user@domain" should strip to "user" for sAMAccountName search.
	var capturedFilter string
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			capturedFilter = req.Filter
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
	}
	c := newTestConnector(mock)

	dn, err := c.resolveUserDN(context.Background(), "jdoe@example.com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if dn != "cn=John Doe,ou=Users,dc=example,dc=com" {
		t.Errorf("unexpected DN: %q", dn)
	}
	// The filter should search for "jdoe", not "jdoe@example.com".
	expectedFilter := "(sAMAccountName=jdoe)"
	if capturedFilter != expectedFilter {
		t.Errorf("expected filter %q, got %q", expectedFilter, capturedFilter)
	}
}

func TestEnableAccount_Success(t *testing.T) {
	// EnableAccount flow:
	//   1. resolveUserDN -> bindAsService + Search (strips @domain)
	//   2. bindAsService (again, for the account modification)
	//   3. Search to read userAccountControl
	//   4. Modify to clear UF_ACCOUNTDISABLE (0x0002)
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(username, password string) error {
			if username != "cn=admin,dc=example,dc=com" || password != "admin-secret" {
				return fmt.Errorf("expected svc bind, got %q / %q", username, password)
			}
			return nil
		},
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				// resolveUserDN search
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			// Second search: read userAccountControl
			entry := ldap.NewEntry("cn=John Doe,ou=Users,dc=example,dc=com", map[string][]string{
				"userAccountControl": {"514"}, // 512 | 2 = disabled normal account
			})
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{entry},
			}, nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			if req.DN != "cn=John Doe,ou=Users,dc=example,dc=com" {
				return fmt.Errorf("unexpected modify DN: %s", req.DN)
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.EnableAccount(context.Background(), "jdoe@example.com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestEnableAccount_ResolveUserDNError(t *testing.T) {
	connector := &mockLDAPConnector{err: fmt.Errorf("connection refused")}
	cfg := idp.Config{
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
		Timeout:        5,
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	c := New("test", cfg, secrets, connector, slog.Default())

	err := c.EnableAccount(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestEnableAccount_SearchError(t *testing.T) {
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			return nil, fmt.Errorf("LDAP search error")
		},
	}
	c := newTestConnector(mock)

	err := c.EnableAccount(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestEnableAccount_UserNotFound(t *testing.T) {
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			// Second search returns empty — user not found
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c := newTestConnector(mock)

	err := c.EnableAccount(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

func TestEnableAccount_InvalidUAC(t *testing.T) {
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			entry := ldap.NewEntry("cn=John Doe,ou=Users,dc=example,dc=com", map[string][]string{
				"userAccountControl": {"not-a-number"},
			})
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	c := newTestConnector(mock)

	err := c.EnableAccount(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error for invalid userAccountControl, got nil")
	}
}

func TestEnableAccount_ModifyError(t *testing.T) {
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			entry := ldap.NewEntry("cn=John Doe,ou=Users,dc=example,dc=com", map[string][]string{
				"userAccountControl": {"514"},
			})
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			return fmt.Errorf("insufficient access rights")
		},
	}
	c := newTestConnector(mock)

	err := c.EnableAccount(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error from Modify, got nil")
	}
}

func TestUnlockAccount_ModifyError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
		modifyFunc: func(req *ldap.ModifyRequest) error {
			return fmt.Errorf("constraint violation")
		},
	}
	c := newTestConnector(mock)

	err := c.UnlockAccount(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error from Modify, got nil")
	}
}

func TestGetUserGroups_SearchError(t *testing.T) {
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				// resolveUserDN search
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			return nil, fmt.Errorf("LDAP error")
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetUserGroups(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetUserGroups_UserNotFound(t *testing.T) {
	searchCall := 0
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCall++
			if searchCall == 1 {
				return &ldap.SearchResult{
					Entries: []*ldap.Entry{
						{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					},
				}, nil
			}
			// Second search: user not found
			return &ldap.SearchResult{Entries: []*ldap.Entry{}}, nil
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetUserGroups(context.Background(), "jdoe@example.com")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

func TestGetGroupMembers_SearchError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, fmt.Errorf("LDAP error")
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetGroupMembers(context.Background(), "cn=Admins,ou=Groups,dc=example,dc=com")
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

	_, err := c.GetGroupMembers(context.Background(), "cn=Admins,ou=Groups,dc=example,dc=com")
	if err == nil {
		t.Fatal("expected error for missing group, got nil")
	}
}

func TestGetUserAttribute_SearchError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, fmt.Errorf("LDAP error")
		},
	}
	c := newTestConnector(mock)

	_, err := c.GetUserAttribute(context.Background(), "cn=John Doe,ou=Users,dc=example,dc=com", "mail")
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

	_, err := c.GetUserAttribute(context.Background(), "cn=John Doe,ou=Users,dc=example,dc=com", "mail")
	if err == nil {
		t.Fatal("expected error for missing user, got nil")
	}
}

func TestSearchUser_MultipleMatches(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=John Doe,ou=Users,dc=example,dc=com"},
					{DN: "cn=John Doe2,ou=Users,dc=example,dc=com"},
				},
			}, nil
		},
	}
	c := newTestConnector(mock)

	_, err := c.SearchUser(context.Background(), "sAMAccountName", "jdoe")
	if err == nil {
		t.Fatal("expected error for multiple matches, got nil")
	}
	if err != idp.ErrMultipleMatches {
		t.Errorf("expected ErrMultipleMatches, got: %v", err)
	}
}

// TestAuthenticate_ConnectError covers the c.connect error branch in Authenticate.
func TestAuthenticate_ConnectError(t *testing.T) {
	// Pass a DN-format user so resolveUserDN returns immediately without connecting.
	// Then the connect for the actual auth bind fails.
	connErr := fmt.Errorf("connection refused")
	connector := &mockLDAPConnector{err: connErr}
	logger := slog.Default()
	cfg := idp.Config{
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	c := New("test-ad", cfg, secrets, connector, logger)

	err := c.Authenticate(context.Background(), "cn=user,dc=example,dc=com", "pass")
	if err == nil {
		t.Error("expected error when connection fails, got nil")
	}
}

// TestChangePassword_ConnectError covers the c.connect error branch in ChangePassword.
func TestChangePassword_ConnectError(t *testing.T) {
	connErr := fmt.Errorf("connection refused")
	connector := &mockLDAPConnector{err: connErr}
	cfg := idp.Config{
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	c := New("test-ad", cfg, secrets, connector, slog.Default())

	err := c.ChangePassword(context.Background(), "cn=user,dc=example,dc=com", "old", "new")
	if err == nil {
		t.Error("expected error when connection fails, got nil")
	}
}

// TestChangePassword_UserBindError covers the user bind failure branch in ChangePassword.
func TestChangePassword_UserBindError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(username, _ string) error {
			// Fail on user bind (not service account).
			if username != "cn=admin,dc=example,dc=com" {
				return fmt.Errorf("invalid credentials for %s", username)
			}
			return nil
		},
	}
	c := newTestConnector(mock)

	err := c.ChangePassword(context.Background(), "cn=user,dc=example,dc=com", "old", "new")
	if err == nil {
		t.Error("expected error when user bind fails, got nil")
	}
}

// TestChangePassword_ModifyError covers the Modify error branch in ChangePassword.
func TestChangePassword_ModifyError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		modifyFunc: func(req *ldap.ModifyRequest) error {
			return fmt.Errorf("modify failed: password policy violation")
		},
	}
	c := newTestConnector(mock)

	err := c.ChangePassword(context.Background(), "cn=user,dc=example,dc=com", "old", "new")
	if err == nil {
		t.Error("expected error when Modify fails, got nil")
	}
}

// TestResetPassword_BindAsServiceError covers the bindAsService error in ResetPassword.
func TestResetPassword_BindAsServiceError(t *testing.T) {
	connErr := fmt.Errorf("connection refused")
	connector := &mockLDAPConnector{err: connErr}
	cfg := idp.Config{
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	c := New("test-ad", cfg, secrets, connector, slog.Default())

	err := c.ResetPassword(context.Background(), "cn=user,dc=example,dc=com", "new-pass")
	if err == nil {
		t.Error("expected error when bindAsService fails, got nil")
	}
}

// TestResetPassword_ModifyError covers the Modify error branch in ResetPassword.
func TestResetPassword_ModifyError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		modifyFunc: func(req *ldap.ModifyRequest) error {
			return fmt.Errorf("password policy violation")
		},
	}
	c := newTestConnector(mock)

	err := c.ResetPassword(context.Background(), "cn=user,dc=example,dc=com", "new-pass")
	if err == nil {
		t.Error("expected error when Modify fails, got nil")
	}
}

// TestAuthenticate_BindError covers the conn.Bind error path in Authenticate.
func TestAuthenticate_BindError(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error {
			return fmt.Errorf("invalid credentials")
		},
	}
	c := newTestConnector(mock)

	err := c.Authenticate(context.Background(), "cn=user,dc=example,dc=com", "wrong-pass")
	if err == nil {
		t.Error("expected error when Bind fails, got nil")
	}
}

// TestUnlockAccount_BindAsServiceError covers the bindAsService error path in UnlockAccount.
func TestUnlockAccount_BindAsServiceError(t *testing.T) {
	connErr := fmt.Errorf("service bind refused")
	connector := &mockLDAPConnector{err: connErr}
	cfg := idp.Config{
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	c := New("test-ad", cfg, secrets, connector, slog.Default())

	err := c.UnlockAccount(context.Background(), "cn=user,dc=example,dc=com")
	if err == nil {
		t.Error("expected error when bindAsService fails, got nil")
	}
}

// TestGetUserGroups_BindAsServiceError covers the bindAsService error path in GetUserGroups.
func TestGetUserGroups_BindAsServiceError(t *testing.T) {
	connErr := fmt.Errorf("service bind refused")
	connector := &mockLDAPConnector{err: connErr}
	cfg := idp.Config{
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "ou=Users,dc=example,dc=com",
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	c := New("test-ad", cfg, secrets, connector, slog.Default())

	_, err := c.GetUserGroups(context.Background(), "cn=user,dc=example,dc=com")
	if err == nil {
		t.Error("expected error when bindAsService fails, got nil")
	}
}

// TestSearchUser_EmptySearchBase covers the UserSearchBase fallback branch in SearchUser.
func TestSearchUser_EmptySearchBase(t *testing.T) {
	entry := ldap.NewEntry("cn=user,dc=example,dc=com", nil)
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
		},
	}
	cfg := idp.Config{
		Endpoint:       "dc.example.com:636",
		Protocol:       "ldaps",
		BaseDN:         "dc=example,dc=com",
		UserSearchBase: "", // empty — should fall back to BaseDN
	}
	secrets := idp.Secrets{
		ServiceAccountUsername: "cn=admin,dc=example,dc=com",
		ServiceAccountPassword: "admin-secret",
	}
	connector := &mockLDAPConnector{conn: mock}
	c := New("test-ad", cfg, secrets, connector, slog.Default())

	dn, err := c.SearchUser(context.Background(), "sAMAccountName", "jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dn != "cn=user,dc=example,dc=com" {
		t.Errorf("expected DN, got %s", dn)
	}
}
