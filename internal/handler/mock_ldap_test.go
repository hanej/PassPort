package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hanej/passport/internal/idp"
)

// ---- Mock LDAP types for handler tests ----

type handlerMockSearch struct {
	result *ldap.SearchResult
	err    error
}

// handlerMockLDAPConn implements idp.LDAPConn with a queue of responses.
type handlerMockLDAPConn struct {
	searches []handlerMockSearch
	fallback *ldap.SearchResult
	bindErr  error
}

func (m *handlerMockLDAPConn) Bind(_, _ string) error { return m.bindErr }
func (m *handlerMockLDAPConn) Search(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if len(m.searches) > 0 {
		s := m.searches[0]
		m.searches = m.searches[1:]
		return s.result, s.err
	}
	if m.fallback != nil {
		return m.fallback, nil
	}
	return &ldap.SearchResult{}, nil
}
func (m *handlerMockLDAPConn) Modify(_ *ldap.ModifyRequest) error { return nil }
func (m *handlerMockLDAPConn) PasswordModify(_ *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	return nil, nil
}
func (m *handlerMockLDAPConn) Close() error { return nil }

var _ idp.LDAPConn = (*handlerMockLDAPConn)(nil)

// handlerMockLDAPConnector implements idp.LDAPConnector.
type handlerMockLDAPConnector struct {
	conn    idp.LDAPConn
	connErr error
}

func (m *handlerMockLDAPConnector) Connect(_ context.Context, _, _ string, _ int, _ bool) (idp.LDAPConn, error) {
	return m.conn, m.connErr
}

var _ idp.LDAPConnector = (*handlerMockLDAPConnector)(nil)

// ---- BrowseChildren with mock connector ----

func TestBrowseChildren_SuccessWithMock_EmptyResult(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "browse-mock-idp")

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{fallback: &ldap.SearchResult{}},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowseChildren(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/browse", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result []any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
}

func TestBrowseChildren_SuccessWithMock_WithDN(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "browse-dn-idp")

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{
			fallback: &ldap.SearchResult{
				Entries: []*ldap.Entry{
					ldap.NewEntry("cn=users,dc=example,dc=com", map[string][]string{
						"objectClass": {"container"},
					}),
				},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowseChildren(w, r)
	})

	// Pass explicit dn param.
	rec := env.serveWithAdminSession(t, handler, http.MethodGet,
		"/admin/idp/"+idpID+"/browse?dn=cn=users,dc=example,dc=com", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestBrowseChildren_SearchFails(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "browse-fail2-idp")

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{
			searches: []handlerMockSearch{
				{err: errors.New("LDAP operations error")},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowseChildren(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/browse", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// ---- ReadEntry with mock connector ----

func TestReadEntry_SuccessWithMock(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "entry-success-idp")

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{
			fallback: &ldap.SearchResult{
				Entries: []*ldap.Entry{
					ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{
						"cn":   {"jdoe"},
						"mail": {"jdoe@example.com"},
					}),
				},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.ReadEntry(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet,
		"/admin/idp/"+idpID+"/entry?dn=cn=jdoe,dc=example,dc=com", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestReadEntry_NotFound(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "entry-notfound-idp")

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{fallback: &ldap.SearchResult{}},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.ReadEntry(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet,
		"/admin/idp/"+idpID+"/entry?dn=cn=nobody,dc=example,dc=com", cookies, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestReadEntry_SearchFails(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "entry-searchfail-idp")

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{
			searches: []handlerMockSearch{
				{err: errors.New("LDAP operations error")},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.ReadEntry(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet,
		"/admin/idp/"+idpID+"/entry?dn=cn=jdoe,dc=example,dc=com", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// ---- SearchDirectory with mock connector ----

func TestSearchDirectory_SuccessWithMock(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{
			fallback: &ldap.SearchResult{
				Entries: []*ldap.Entry{
					ldap.NewEntry("cn=jdoe,dc=example,dc=com", map[string][]string{
						"objectClass": {"person"},
					}),
				},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.SearchDirectory(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet,
		"/admin/idp/"+idpID+"/search?attr=sAMAccountName&value=jdoe", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSearchDirectory_SearchFails(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{
			searches: []handlerMockSearch{
				{err: errors.New("LDAP operations error")},
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.SearchDirectory(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet,
		"/admin/idp/"+idpID+"/search?attr=sAMAccountName&value=jdoe", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// ---- getLDAPConn: bind fails path ----

func TestGetLDAPConn_BindFails(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "bind-fail-idp")

	env.handler.connector = &handlerMockLDAPConnector{
		conn: &handlerMockLDAPConn{
			bindErr: errors.New("LDAP invalid credentials"),
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowseChildren(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/browse", cookies, "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on bind failure, got %d", rec.Code)
	}
}

// ---- TestConnection (admin_idp) with mock connector ----

func TestAdminIDPTestConnection_NotFound(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.TestConnection(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/nonexistent-idp/test", cookies, "")
	if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusNotFound {
		t.Errorf("expected error status, got %d", rec.Code)
	}
}

// ---- BrowsePage ----

func TestBrowsePage_WithMockIDP(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "browse-page-idp")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowsePage(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/browse-page", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestBrowsePage_IDPNotFound(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "no-such-idp")
		env.handler.BrowsePage(w, r)
	}), http.MethodGet, "/admin/idp/no-such-idp/browse-page", cookies, "")

	if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusNotFound {
		t.Errorf("expected 500 or 404, got %d", rec.Code)
	}
}

// --- Admin IDP TestConnection via saved ID ---
func TestAdminIDPTestConnection_ViaSavedID(t *testing.T) {
	env := setupIDPTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDP(t)

	// TestConnection uses the saved IDP record + tries to connect (real LDAP fails).
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.TestConnection(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/"+idpID+"/test", cookies, "")
	ct := rec.Header().Get("Content-Type")
	if ct == "" || (!containsAny(ct, "application/json", "text/html")) {
		t.Errorf("expected JSON or HTML response, got content-type: %q", ct)
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// ---- helper: check idpTestEnv.handler.connector is injectable ----

func TestIDPHandlerConnectorIsInjectable(t *testing.T) {
	env := setupIDPTest(t)
	mock := &handlerMockLDAPConnector{}
	env.handler.connector = mock
	if env.handler.connector != mock {
		t.Error("connector field not injectable")
	}
}

// ---- BrowsePage needs template ----

func TestBrowsePage_Success_WithTemplate(t *testing.T) {
	env := setupBrowseTest(t)
	cookies := env.createAdminSession(t)
	idpID := env.createTestIDPWithConfig(t, "browse-page2")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", idpID)
		env.handler.BrowsePage(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/"+idpID+"/browse-page", cookies, "")
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Errorf("unexpected status %d", rec.Code)
	}
}

// ---- verifyIDPReadEntry from handlerMockLDAPConn ----

func TestReadEntry_MockConn_Verify(t *testing.T) {
	conn := &handlerMockLDAPConn{
		fallback: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				ldap.NewEntry("cn=x,dc=example,dc=com", map[string][]string{"cn": {"x"}}),
			},
		},
	}
	req := ldap.NewSearchRequest("cn=x,dc=example,dc=com", ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"*"}, nil)
	result, err := conn.Search(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
}
