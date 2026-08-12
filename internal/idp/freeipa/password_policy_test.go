package freeipa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

const (
	testUserDN      = "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"
	testRealmDN     = "cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com"
	testGlobalPwDN  = "cn=global_policy,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com"
	testGroupPwDN   = "cn=strict,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com"
	testGroupPwDN2  = "cn=relaxed,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com"
	testCoSBase     = "cn=costemplates,cn=accounts,dc=example,dc=com"
	testAdminsDN    = "cn=admins,cn=groups,cn=accounts,dc=example,dc=com"
	testEngineersDN = "cn=engineers,cn=groups,cn=accounts,dc=example,dc=com"
)

func krbTime(t time.Time) string { return t.UTC().Format("20060102150405Z") }

func policyEntry(dn string, attrs map[string]string) *ldap.SearchResult {
	e := &ldap.Entry{DN: dn}
	for name, val := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: name, Values: []string{val}})
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{e}}
}

func noEntries() *ldap.SearchResult { return &ldap.SearchResult{Entries: []*ldap.Entry{}} }

// coSTemplate builds one Class of Service template entry, whose cn is the DN of
// the group it covers.
func coSTemplate(groupDN, policyDN, priority string) *ldap.Entry {
	e := &ldap.Entry{DN: "cn=" + groupDN + "," + testCoSBase}
	e.Attributes = append(e.Attributes,
		&ldap.EntryAttribute{Name: "cn", Values: []string{groupDN}},
		&ldap.EntryAttribute{Name: policyRefAttr, Values: []string{policyDN}},
	)
	if priority != "" {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "cospriority", Values: []string{priority}})
	}
	return e
}

// policyMock routes each read the way a real FreeIPA server would: the user
// entry, the realm container, the global policy, and any group policy are all
// separate reads.
type policyMock struct {
	user   map[string]string
	global map[string]string
	group  map[string]string
	group2 map[string]string
	// memberOf and costemplates drive the fallback used when the server will not
	// disclose krbPwdPolicyReference on the user entry.
	memberOf       []string
	costemplates   []*ldap.Entry
	costemplateErr error
	// realmMissing simulates a directory with no krbRealmContainer under cn=kerberos.
	realmMissing bool
	// globalMissing simulates a server that will not disclose the global policy
	// entry at all, which is how a missing read privilege presents itself.
	globalMissing bool
}

func (m *policyMock) conn() *mockLDAPConn {
	return &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			switch req.BaseDN {
			case testUserDN:
				res := policyEntry(testUserDN, m.user)
				if len(m.memberOf) > 0 {
					res.Entries[0].Attributes = append(res.Entries[0].Attributes,
						&ldap.EntryAttribute{Name: "memberOf", Values: m.memberOf})
				}
				return res, nil
			case testCoSBase:
				if m.costemplateErr != nil {
					return nil, m.costemplateErr
				}
				return &ldap.SearchResult{Entries: m.costemplates}, nil
			case "cn=kerberos,dc=example,dc=com":
				if m.realmMissing {
					return noEntries(), nil
				}
				return policyEntry(testRealmDN, map[string]string{"cn": "EXAMPLE.COM"}), nil
			case testGlobalPwDN:
				if m.globalMissing {
					return noEntries(), nil
				}
				return policyEntry(testGlobalPwDN, m.global), nil
			case testGroupPwDN:
				return policyEntry(testGroupPwDN, m.group), nil
			case testGroupPwDN2:
				return policyEntry(testGroupPwDN2, m.group2), nil
			}
			return nil, fmt.Errorf("unexpected search base %q", req.BaseDN)
		},
	}
}

// ---- PasswordChangeAllowedAt ----

func TestPasswordChangeAllowedAt_BlocksInsideMinimumLife(t *testing.T) {
	changedAt := time.Now().Add(-1 * time.Hour)
	m := &policyMock{
		user:   map[string]string{"krbLastPwdChange": krbTime(changedAt)},
		global: map[string]string{"krbMinPwdLife": "86400"}, // 24h, stored in seconds
	}

	allowedAt, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowedAt.IsZero() {
		t.Fatal("expected a block one hour into a 24h minimum lifetime")
	}
	if want := changedAt.Add(24 * time.Hour); allowedAt.Sub(want).Abs() > time.Second {
		t.Errorf("allowedAt = %s, want near %s", allowedAt, want)
	}
}

func TestPasswordChangeAllowedAt_AllowsOutsideMinimumLife(t *testing.T) {
	m := &policyMock{
		user:   map[string]string{"krbLastPwdChange": krbTime(time.Now().Add(-48 * time.Hour))},
		global: map[string]string{"krbMinPwdLife": "86400"},
	}

	allowedAt, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowedAt.IsZero() {
		t.Errorf("expected the change to be allowed, got a block until %s", allowedAt)
	}
}

// An expired password must never be blocked: that is exactly when the user has
// to be able to set a new one.
func TestPasswordChangeAllowedAt_ExpiredPasswordIsExempt(t *testing.T) {
	m := &policyMock{
		user: map[string]string{
			"krbLastPwdChange":      krbTime(time.Now().Add(-1 * time.Hour)),
			"krbPasswordExpiration": krbTime(time.Now().Add(-1 * time.Minute)),
		},
		global: map[string]string{"krbMinPwdLife": "86400"},
	}

	allowedAt, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowedAt.IsZero() {
		t.Errorf("an expired password must be exempt, got a block until %s", allowedAt)
	}
}

// A group policy reached through krbPwdPolicyReference wins over the global one,
// and is read without ever touching the realm container.
func TestPasswordChangeAllowedAt_GroupPolicyOverridesGlobal(t *testing.T) {
	changedAt := time.Now().Add(-1 * time.Hour)
	m := &policyMock{
		user: map[string]string{
			"krbLastPwdChange":      krbTime(changedAt),
			policyRefAttr:           testGroupPwDN,
			"krbPasswordExpiration": krbTime(time.Now().Add(30 * 24 * time.Hour)),
		},
		global: map[string]string{"krbMinPwdLife": "0"},
		group:  map[string]string{"krbMinPwdLife": "172800"}, // 48h
	}

	allowedAt, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := changedAt.Add(48 * time.Hour); allowedAt.Sub(want).Abs() > time.Second {
		t.Errorf("allowedAt = %s, want the group policy's %s", allowedAt, want)
	}
}

func TestPasswordChangeAllowedAt_NoMinimumLife(t *testing.T) {
	tests := []struct {
		name   string
		user   map[string]string
		global map[string]string
	}{
		{
			name:   "attribute absent",
			user:   map[string]string{"krbLastPwdChange": krbTime(time.Now())},
			global: map[string]string{},
		},
		{
			name:   "explicitly zero",
			user:   map[string]string{"krbLastPwdChange": krbTime(time.Now())},
			global: map[string]string{"krbMinPwdLife": "0"},
		},
		{
			name:   "absurd value is ignored rather than overflowing a Duration",
			user:   map[string]string{"krbLastPwdChange": krbTime(time.Now())},
			global: map[string]string{"krbMinPwdLife": "999999999999"},
		},
		{
			name:   "no Kerberos password has ever been set",
			user:   map[string]string{},
			global: map[string]string{"krbMinPwdLife": "86400"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &policyMock{user: tt.user, global: tt.global}
			allowedAt, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !allowedAt.IsZero() {
				t.Errorf("expected no block, got %s", allowedAt)
			}
		})
	}
}

func TestPasswordChangeAllowedAt_Errors(t *testing.T) {
	t.Run("service bind fails", func(t *testing.T) {
		conn := &mockLDAPConn{bindFunc: func(_, _ string) error { return fmt.Errorf("invalid credentials") }}
		if _, err := newTestConnector(conn).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the service account cannot bind")
		}
	})

	t.Run("user entry missing", func(t *testing.T) {
		conn := &mockLDAPConn{
			bindFunc:   func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) { return noEntries(), nil },
		}
		if _, err := newTestConnector(conn).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the user entry is missing")
		}
	})

	t.Run("user entry read fails", func(t *testing.T) {
		conn := &mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, fmt.Errorf("ldap: server down")
			},
		}
		if _, err := newTestConnector(conn).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the user entry cannot be read")
		}
	})

	t.Run("krbLastPwdChange is unparseable", func(t *testing.T) {
		m := &policyMock{
			user:   map[string]string{"krbLastPwdChange": "not-a-time"},
			global: map[string]string{"krbMinPwdLife": "86400"},
		}
		if _, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error parsing a malformed krbLastPwdChange")
		}
	})

	t.Run("krbMinPwdLife is not a number", func(t *testing.T) {
		m := &policyMock{
			user:   map[string]string{"krbLastPwdChange": krbTime(time.Now())},
			global: map[string]string{"krbMinPwdLife": "soon"},
		}
		if _, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error parsing a non-numeric krbMinPwdLife")
		}
	})

	t.Run("no realm container", func(t *testing.T) {
		m := &policyMock{
			user:         map[string]string{"krbLastPwdChange": krbTime(time.Now())},
			realmMissing: true,
		}
		if _, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the realm container cannot be found")
		}
	})

	t.Run("realm container read fails", func(t *testing.T) {
		conn := &mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.BaseDN == testUserDN {
					return policyEntry(testUserDN, map[string]string{"krbLastPwdChange": krbTime(time.Now())}), nil
				}
				return nil, fmt.Errorf("ldap: insufficient access rights")
			},
		}
		if _, err := newTestConnector(conn).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the realm container cannot be read")
		}
	})
}

// ---- ResolvePasswordPolicy ----

func TestResolvePasswordPolicy(t *testing.T) {
	tests := []struct {
		name string
		mock *policyMock
		want idp.PasswordPolicy
	}{
		{
			name: "global policy with character classes",
			mock: &policyMock{
				user: map[string]string{"uid": "jdoe", "displayName": "Jane Doe"},
				global: map[string]string{
					"krbPwdMinLength":    "12",
					"krbPwdMinDiffChars": "3",
				},
			},
			want: idp.PasswordPolicy{
				MinLength: 12, ComplexityEnabled: true, MinCategories: 3,
				SamAccountName: "jdoe", DisplayName: "Jane Doe",
			},
		},
		{
			name: "length only, no complexity",
			mock: &policyMock{
				user:   map[string]string{"uid": "jdoe"},
				global: map[string]string{"krbPwdMinLength": "8", "krbPwdMinDiffChars": "0"},
			},
			want: idp.PasswordPolicy{MinLength: 8, SamAccountName: "jdoe"},
		},
		{
			name: "ipaPwdUserCheck alone enables the name rule",
			mock: &policyMock{
				user:   map[string]string{"uid": "jdoe"},
				global: map[string]string{"krbPwdMinLength": "10", "ipaPwdUserCheck": "TRUE"},
			},
			want: idp.PasswordPolicy{
				MinLength: 10, ComplexityEnabled: true, ForbidsUserName: true, SamAccountName: "jdoe",
			},
		},
		{
			name: "group policy overrides the global one",
			mock: &policyMock{
				user:   map[string]string{"uid": "jdoe", policyRefAttr: testGroupPwDN},
				global: map[string]string{"krbPwdMinLength": "8"},
				group:  map[string]string{"krbPwdMinLength": "16", "krbPwdMinDiffChars": "4"},
			},
			want: idp.PasswordPolicy{
				MinLength: 16, ComplexityEnabled: true, MinCategories: 4, SamAccountName: "jdoe",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newTestConnector(tt.mock.conn()).ResolvePasswordPolicy(context.Background(), testUserDN)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("policy = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResolvePasswordPolicy_Errors(t *testing.T) {
	t.Run("service bind fails", func(t *testing.T) {
		conn := &mockLDAPConn{bindFunc: func(_, _ string) error { return fmt.Errorf("invalid credentials") }}
		if _, err := newTestConnector(conn).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the service account cannot bind")
		}
	})

	t.Run("user entry missing", func(t *testing.T) {
		conn := &mockLDAPConn{
			bindFunc:   func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) { return noEntries(), nil },
		}
		if _, err := newTestConnector(conn).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the user entry is missing")
		}
	})

	t.Run("no realm container", func(t *testing.T) {
		m := &policyMock{user: map[string]string{"uid": "jdoe"}, realmMissing: true}
		if _, err := newTestConnector(m.conn()).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the realm container cannot be found")
		}
	})

	// A withheld minimum length must read as "unknown" rather than as zero, or the
	// page would tell the user their password needs at least 0 characters.
	t.Run("minimum length withheld", func(t *testing.T) {
		m := &policyMock{
			user:   map[string]string{"uid": "jdoe"},
			global: map[string]string{"krbPwdMinDiffChars": "3"},
		}
		if _, err := newTestConnector(m.conn()).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when krbPwdMinLength is absent")
		}
	})

	t.Run("minimum length is not a number", func(t *testing.T) {
		m := &policyMock{
			user:   map[string]string{"uid": "jdoe"},
			global: map[string]string{"krbPwdMinLength": "eight"},
		}
		if _, err := newTestConnector(m.conn()).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error parsing a non-numeric krbPwdMinLength")
		}
	})

	t.Run("character class count is not a number", func(t *testing.T) {
		m := &policyMock{
			user:   map[string]string{"uid": "jdoe"},
			global: map[string]string{"krbPwdMinLength": "8", "krbPwdMinDiffChars": "three"},
		}
		if _, err := newTestConnector(m.conn()).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error parsing a non-numeric krbPwdMinDiffChars")
		}
	})

	t.Run("policy entry read fails", func(t *testing.T) {
		conn := &mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				switch req.BaseDN {
				case testUserDN:
					return policyEntry(testUserDN, map[string]string{"uid": "jdoe", policyRefAttr: testGroupPwDN}), nil
				}
				return nil, fmt.Errorf("ldap: insufficient access rights")
			},
		}
		if _, err := newTestConnector(conn).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the policy entry cannot be read")
		}
	})
}

// ---- interface compliance ----

func TestConnectorImplementsPolicyInterfaces(t *testing.T) {
	var c any = newTestConnector(&mockLDAPConn{})
	if _, ok := c.(idp.PasswordPolicyReader); !ok {
		t.Error("FreeIPA connector must implement idp.PasswordPolicyReader")
	}
	if _, ok := c.(idp.PasswordAgePolicy); !ok {
		t.Error("FreeIPA connector must implement idp.PasswordAgePolicy")
	}
}

// ---- parseGeneralizedTime ----

func TestParseGeneralizedTime(t *testing.T) {
	tests := []struct {
		raw     string
		wantErr bool
	}{
		{raw: "20260415120000Z"},
		{raw: "20260415120000+0000"},
		{raw: "20260415120000-0500"},
		{raw: "not-a-time", wantErr: true},
		{raw: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseGeneralizedTime(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected an error for %q", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.IsZero() {
				t.Errorf("parsed %q to the zero time", tt.raw)
			}
		})
	}
}

// ---- group policy resolution without krbPwdPolicyReference ----

// Reading krbPwdPolicyReference off a user entry needs the User Administrators
// privilege. Without it the attribute is simply absent, so the policy has to be
// derived from the Class of Service templates instead of silently falling
// through to the global policy the user is not actually subject to.
func TestResolvePasswordPolicy_CoSTemplateFallback(t *testing.T) {
	tests := map[string]struct {
		memberOf     []string
		costemplates []*ldap.Entry
		wantLength   int
	}{
		"template for a group the user belongs to": {
			memberOf:     []string{testEngineersDN},
			costemplates: []*ldap.Entry{coSTemplate(testEngineersDN, testGroupPwDN, "10")},
			wantLength:   16,
		},
		"lowest cospriority wins": {
			memberOf: []string{testAdminsDN, testEngineersDN},
			costemplates: []*ldap.Entry{
				coSTemplate(testAdminsDN, testGroupPwDN2, "20"),
				coSTemplate(testEngineersDN, testGroupPwDN, "10"),
			},
			wantLength: 16,
		},
		"a template without a priority loses to one with": {
			memberOf: []string{testAdminsDN, testEngineersDN},
			costemplates: []*ldap.Entry{
				coSTemplate(testAdminsDN, testGroupPwDN2, ""),
				coSTemplate(testEngineersDN, testGroupPwDN, "10"),
			},
			wantLength: 16,
		},
		"DNs compare case and whitespace insensitively": {
			memberOf:     []string{"CN=Engineers, CN=Groups, CN=Accounts, DC=Example, DC=com"},
			costemplates: []*ldap.Entry{coSTemplate(testEngineersDN, testGroupPwDN, "10")},
			wantLength:   16,
		},
		"no template matches, so the global policy applies": {
			memberOf:     []string{testAdminsDN},
			costemplates: []*ldap.Entry{coSTemplate(testEngineersDN, testGroupPwDN, "10")},
			wantLength:   8,
		},
		"a template with no policy reference is ignored": {
			memberOf: []string{testEngineersDN},
			costemplates: []*ldap.Entry{
				{DN: "cn=" + testEngineersDN + "," + testCoSBase, Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{testEngineersDN}},
				}},
			},
			wantLength: 8,
		},
		"an unparsable template cn is ignored": {
			memberOf:     []string{testEngineersDN},
			costemplates: []*ldap.Entry{coSTemplate("not a dn", testGroupPwDN, "10")},
			wantLength:   8,
		},
		"no group memberships at all": {
			memberOf:     nil,
			costemplates: nil,
			wantLength:   8,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m := &policyMock{
				user:         map[string]string{"uid": "jdoe"},
				memberOf:     tc.memberOf,
				costemplates: tc.costemplates,
				global:       map[string]string{"krbPwdMinLength": "8"},
				group:        map[string]string{"krbPwdMinLength": "16"},
				group2:       map[string]string{"krbPwdMinLength": "32"},
			}
			c := newTestConnector(m.conn())

			got, err := c.ResolvePasswordPolicy(context.Background(), testUserDN)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if got.MinLength != tc.wantLength {
				t.Errorf("expected length %d, got %d", tc.wantLength, got.MinLength)
			}
		})
	}
}

// krbPwdPolicyReference is authoritative when the directory does disclose it,
// so the templates must not be consulted at all.
func TestResolvePasswordPolicy_ReferenceBeatsCoSTemplate(t *testing.T) {
	m := &policyMock{
		user:     map[string]string{"uid": "jdoe", policyRefAttr: testGroupPwDN},
		memberOf: []string{testAdminsDN},
		costemplates: []*ldap.Entry{
			coSTemplate(testAdminsDN, testGroupPwDN2, "1"),
		},
		group:  map[string]string{"krbPwdMinLength": "16"},
		group2: map[string]string{"krbPwdMinLength": "32"},
	}
	c := newTestConnector(m.conn())

	got, err := c.ResolvePasswordPolicy(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.MinLength != 16 {
		t.Errorf("expected the referenced policy's length 16, got %d", got.MinLength)
	}
}

// A realm with no group policies has no costemplates container at all.
func TestResolvePasswordPolicy_MissingCoSContainerFallsBack(t *testing.T) {
	m := &policyMock{
		user:           map[string]string{"uid": "jdoe"},
		memberOf:       []string{testEngineersDN},
		costemplateErr: ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("no such object")),
		global:         map[string]string{"krbPwdMinLength": "8"},
	}
	c := newTestConnector(m.conn())

	got, err := c.ResolvePasswordPolicy(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.MinLength != 8 {
		t.Errorf("expected the global policy's length 8, got %d", got.MinLength)
	}
}

// Any other failure reading the templates is reported, because carrying on
// would describe the wrong policy.
func TestResolvePasswordPolicy_CoSTemplateReadError(t *testing.T) {
	m := &policyMock{
		user:           map[string]string{"uid": "jdoe"},
		memberOf:       []string{testEngineersDN},
		costemplateErr: ldap.NewError(ldap.LDAPResultBusy, fmt.Errorf("server busy")),
		global:         map[string]string{"krbPwdMinLength": "8"},
	}
	c := newTestConnector(m.conn())

	if _, err := c.ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
		t.Fatal("expected an error when the templates cannot be read")
	}
}

// The same fallback has to apply to the minimum-age gate, or a user under a
// group policy would be measured against the global minimum lifetime.
func TestPasswordChangeAllowedAt_UsesCoSTemplatePolicy(t *testing.T) {
	changedAt := time.Now().Add(-1 * time.Hour)
	m := &policyMock{
		user:         map[string]string{"krbLastPwdChange": krbTime(changedAt)},
		memberOf:     []string{testEngineersDN},
		costemplates: []*ldap.Entry{coSTemplate(testEngineersDN, testGroupPwDN, "10")},
		global:       map[string]string{"krbMinPwdLife": "0"},
		group:        map[string]string{"krbMinPwdLife": "86400"},
	}
	c := newTestConnector(m.conn())

	allowedAt, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if allowedAt.IsZero() {
		t.Fatal("expected the group policy's 24h minimum lifetime to block the change")
	}
}

// FreeIPA allows minclasses up to 5 because MIT Kerberos counts a fifth class
// outside printable ASCII. The checklist only shows four, so a rule it could
// never tick has to be capped rather than displayed.
func TestResolvePasswordPolicy_ClampsCharacterClasses(t *testing.T) {
	m := &policyMock{
		user:   map[string]string{"uid": "jdoe"},
		global: map[string]string{"krbPwdMinLength": "8", "krbPwdMinDiffChars": "5"},
	}
	c := newTestConnector(m.conn())

	got, err := c.ResolvePasswordPolicy(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.MinCategories != 4 {
		t.Errorf("expected the category count capped at 4, got %d", got.MinCategories)
	}
}

// ---- Diagnose ----

func TestDiagnose(t *testing.T) {
	tests := []struct {
		name        string
		mock        *policyMock
		wantWarning bool
	}{
		{
			name:        "policy readable",
			mock:        &policyMock{global: map[string]string{"krbPwdMinLength": "8"}},
			wantWarning: false,
		},
		{
			name:        "realm container hidden",
			mock:        &policyMock{realmMissing: true},
			wantWarning: true,
		},
		{
			name:        "policy entry hidden",
			mock:        &policyMock{globalMissing: true},
			wantWarning: true,
		},
		{
			name:        "policy entry visible but attributes are not",
			mock:        &policyMock{global: map[string]string{}},
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := newTestConnector(tt.mock.conn()).Diagnose(context.Background())
			if tt.wantWarning {
				if len(warnings) == 0 {
					t.Fatal("expected a warning, got none")
				}
				if !strings.Contains(warnings[0], "Password Policy Readers") {
					t.Errorf("warning should name the privilege to grant, got %q", warnings[0])
				}
			} else if len(warnings) != 0 {
				t.Errorf("expected no warnings, got %v", warnings)
			}
		})
	}
}

// A bind failure is the connection test's own result, so Diagnose must not
// duplicate it as a policy problem.
func TestDiagnose_BindFailureIsNotReported(t *testing.T) {
	conn := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return errors.New("invalid credentials") },
	}
	if warnings := newTestConnector(conn).Diagnose(context.Background()); warnings != nil {
		t.Errorf("expected no warnings on a failed bind, got %v", warnings)
	}
}

func TestConnectorImplementsDirectoryDiagnoser(t *testing.T) {
	var _ idp.DirectoryDiagnoser = (*Connector)(nil)
}
