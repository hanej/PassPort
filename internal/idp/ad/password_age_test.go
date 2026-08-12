package ad

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Values observed on a live 2016-functional-level domain:
//
//	minPwdAge   -864000000000  (24h, domain head)
//	pwdLastSet  134302484933800903
const (
	realMinPwdAge24h = "-864000000000"
	testDomainDN     = "dc=example,dc=com"
	testUserDN       = "cn=user,dc=example,dc=com"
	testPSODN        = "cn=strict,cn=Password Settings Container,cn=System,dc=example,dc=com"
)

func timeToFiletime(t time.Time) string {
	return fmt.Sprintf("%d", (t.Unix()+filetimeEpochOffset)*1e7)
}

func entry(dn string, attrs map[string]string) *ldap.SearchResult {
	e := &ldap.Entry{DN: dn}
	for name, val := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: name, Values: []string{val}})
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{e}}
}

// ageMock routes each base-scope search the way a real directory would: the user
// object, the RootDSE, the domain head, and any PSO are all separate reads.
type ageMock struct {
	user   map[string]string
	domain map[string]string
	pso    map[string]string
	bases  []string
}

func (m *ageMock) conn() *mockLDAPConn {
	return &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			m.bases = append(m.bases, req.BaseDN)
			switch req.BaseDN {
			case testUserDN:
				return entry(testUserDN, m.user), nil
			case "":
				return entry("", map[string]string{"defaultNamingContext": testDomainDN}), nil
			case testDomainDN:
				return entry(testDomainDN, m.domain), nil
			case testPSODN:
				return entry(testPSODN, m.pso), nil
			}
			return nil, fmt.Errorf("unexpected search base %q", req.BaseDN)
		},
	}
}

func TestPasswordChangeAllowedAt_BlocksInsideMinimumAge(t *testing.T) {
	changedAt := time.Now().Add(-1 * time.Hour)
	m := &ageMock{
		user:   map[string]string{"pwdLastSet": timeToFiletime(changedAt)},
		domain: map[string]string{"minPwdAge": realMinPwdAge24h},
	}
	c := newTestConnector(m.conn())

	allowedAt, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if allowedAt.IsZero() {
		t.Fatal("expected a block one hour into a 24h minimum age")
	}
	// The directory allows the change 24h after the password was last set.
	if want := changedAt.Add(24 * time.Hour); allowedAt.Sub(want).Abs() > time.Second {
		t.Errorf("expected allowedAt near %s, got %s", want, allowedAt)
	}
}

func TestPasswordChangeAllowedAt_AllowsOutsideMinimumAge(t *testing.T) {
	m := &ageMock{
		user:   map[string]string{"pwdLastSet": timeToFiletime(time.Now().Add(-48 * time.Hour))},
		domain: map[string]string{"minPwdAge": realMinPwdAge24h},
	}
	c := newTestConnector(m.conn())

	allowedAt, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !allowedAt.IsZero() {
		t.Errorf("expected no block 48h into a 24h minimum age, got %s", allowedAt)
	}
}

// pwdLastSet=0 is "must change at next logon", which AD exempts from minimum age.
// This is also the state Passport's own reset flow leaves behind between the
// temporary password and the user's new one.
func TestPasswordChangeAllowedAt_MustChangeAtNextLogon(t *testing.T) {
	m := &ageMock{user: map[string]string{"pwdLastSet": "0"}}
	c := newTestConnector(m.conn())

	allowedAt, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !allowedAt.IsZero() {
		t.Errorf("expected no block when pwdLastSet is 0, got %s", allowedAt)
	}
	for _, base := range m.bases {
		if base == testDomainDN {
			t.Error("should not read the domain policy once pwdLastSet is 0")
		}
	}
}

func TestPasswordChangeAllowedAt_PSOOverridesDomain(t *testing.T) {
	changedAt := time.Now().Add(-3 * time.Hour)
	m := &ageMock{
		user: map[string]string{
			"pwdLastSet":        timeToFiletime(changedAt),
			"msDS-ResultantPSO": testPSODN,
		},
		// The domain would permit the change; the PSO must win.
		domain: map[string]string{"minPwdAge": "-36000000000"},
		pso:    map[string]string{"msDS-MinimumPasswordAge": realMinPwdAge24h},
	}
	c := newTestConnector(m.conn())

	allowedAt, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if want := changedAt.Add(24 * time.Hour); allowedAt.Sub(want).Abs() > time.Second {
		t.Errorf("expected the PSO's 24h age, got %s", allowedAt)
	}
	for _, base := range m.bases {
		if base == testDomainDN {
			t.Error("should not fall back to the domain policy when a PSO applies")
		}
	}
}

// A PSO that resolves but yields no minimum age means the attribute was withheld.
// Returning "no minimum age" there would drop the check for the restricted users a
// PSO exists to cover, so it must surface as an error and let the handler fail closed.
func TestPasswordChangeAllowedAt_PSOWithheldIsAnError(t *testing.T) {
	m := &ageMock{
		user: map[string]string{
			"pwdLastSet":        timeToFiletime(time.Now()),
			"msDS-ResultantPSO": testPSODN,
		},
		domain: map[string]string{"minPwdAge": realMinPwdAge24h},
		pso:    map[string]string{},
	}
	c := newTestConnector(m.conn())

	if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
		t.Error("expected an error when the PSO withholds msDS-MinimumPasswordAge, got nil")
	}
}

func TestPasswordChangeAllowedAt_NoMinimumAgeConfigured(t *testing.T) {
	for name, minPwdAge := range map[string]string{
		"zero":           "0",
		"absent":         "",
		"absurdly large": "-9223372036854775808",
	} {
		t.Run(name, func(t *testing.T) {
			m := &ageMock{
				user:   map[string]string{"pwdLastSet": timeToFiletime(time.Now())},
				domain: map[string]string{"minPwdAge": minPwdAge},
			}
			c := newTestConnector(m.conn())

			allowedAt, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if !allowedAt.IsZero() {
				t.Errorf("expected no block, got %s", allowedAt)
			}
		})
	}
}

// The handler fails closed on error, so every failure path must actually report one.
func TestPasswordChangeAllowedAt_Errors(t *testing.T) {
	tests := map[string]*mockLDAPConn{
		"search fails": {
			bindFunc:   func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) { return nil, fmt.Errorf("boom") },
		},
		"user missing": {
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{}, nil
			},
		},
		"pwdLastSet unparseable": {
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return entry(testUserDN, map[string]string{"pwdLastSet": "not-a-number"}), nil
			},
		},
		"service bind fails": {
			bindFunc: func(_, _ string) error { return fmt.Errorf("invalid credentials") },
		},
	}

	for name, mock := range tests {
		t.Run(name, func(t *testing.T) {
			c := newTestConnector(mock)
			if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

func TestPasswordChangeAllowedAt_RootDSEUnusable(t *testing.T) {
	mock := &mockLDAPConn{
		bindFunc: func(_, _ string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if req.BaseDN == testUserDN {
				return entry(testUserDN, map[string]string{
					"pwdLastSet": timeToFiletime(time.Now()),
				}), nil
			}
			return entry("", map[string]string{}), nil
		},
	}
	c := newTestConnector(mock)
	if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
		t.Error("expected an error when defaultNamingContext is missing, got nil")
	}
}

func TestFiletimeToTime(t *testing.T) {
	// The value the live directory reported for a password set at 16:34:53 UTC.
	got := filetimeToTime(134302484933800903)
	want := time.Date(2026, 8, 3, 16, 34, 53, 0, time.UTC)
	if got.Truncate(time.Second) != want {
		t.Errorf("expected %s, got %s", want, got)
	}
}

// Live domain values: 12 at the domain head, 16 and 24 under fine-grained policies.
func TestResolvePasswordPolicy(t *testing.T) {
	tests := map[string]struct {
		user           map[string]string
		pso            map[string]string
		domain         map[string]string
		wantLength     int
		wantComplexity bool
		wantAccount    string
		wantDisplay    string
	}{
		"domain default": {
			user:           map[string]string{"sAMAccountName": "jvidal", "displayName": "Jorge Vidal"},
			domain:         map[string]string{"minPwdLength": "12", "pwdProperties": "1"},
			wantLength:     12,
			wantComplexity: true,
			wantAccount:    "jvidal",
			wantDisplay:    "Jorge Vidal",
		},
		"domain complexity disabled": {
			user:       map[string]string{},
			domain:     map[string]string{"minPwdLength": "12", "pwdProperties": "0"},
			wantLength: 12,
		},
		"fine-grained policy wins": {
			user:   map[string]string{"msDS-ResultantPSO": testPSODN},
			domain: map[string]string{"minPwdLength": "12", "pwdProperties": "0"},
			pso: map[string]string{
				"msDS-MinimumPasswordLength":     "24",
				"msDS-PasswordComplexityEnabled": "TRUE",
			},
			wantLength:     24,
			wantComplexity: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m := &ageMock{user: tc.user, domain: tc.domain, pso: tc.pso}
			c := newTestConnector(m.conn())

			got, err := c.ResolvePasswordPolicy(context.Background(), testUserDN)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if got.MinLength != tc.wantLength {
				t.Errorf("expected length %d, got %d", tc.wantLength, got.MinLength)
			}
			if got.ComplexityEnabled != tc.wantComplexity {
				t.Errorf("expected complexity %v, got %v", tc.wantComplexity, got.ComplexityEnabled)
			}
			if got.SamAccountName != tc.wantAccount {
				t.Errorf("expected account %q, got %q", tc.wantAccount, got.SamAccountName)
			}
			if got.DisplayName != tc.wantDisplay {
				t.Errorf("expected display name %q, got %q", tc.wantDisplay, got.DisplayName)
			}
			// AD's complexity rule is fixed at three categories plus the name check,
			// so the two must move together with ComplexityEnabled.
			wantCategories := 0
			if tc.wantComplexity {
				wantCategories = 3
			}
			if got.MinCategories != wantCategories {
				t.Errorf("expected %d categories, got %d", wantCategories, got.MinCategories)
			}
			if got.ForbidsUserName != tc.wantComplexity {
				t.Errorf("expected ForbidsUserName %v, got %v", tc.wantComplexity, got.ForbidsUserName)
			}
		})
	}
}

// The caller falls back to its configured length, so these must report an error
// rather than a zero length that would silently shorten the generated password.
func TestResolvePasswordPolicy_Errors(t *testing.T) {
	tests := map[string]*mockLDAPConn{
		"search fails": {
			bindFunc:   func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) { return nil, fmt.Errorf("boom") },
		},
		"attribute withheld": {
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return entry(testUserDN, map[string]string{"defaultNamingContext": testDomainDN}), nil
			},
		},
		"unparseable length": {
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.BaseDN == "" {
					return entry("", map[string]string{"defaultNamingContext": testDomainDN}), nil
				}
				return entry(req.BaseDN, map[string]string{"minPwdLength": "twelve"}), nil
			},
		},
		"unparseable pwdProperties": {
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.BaseDN == "" {
					return entry("", map[string]string{"defaultNamingContext": testDomainDN}), nil
				}
				return entry(req.BaseDN, map[string]string{"minPwdLength": "12", "pwdProperties": "yes"}), nil
			},
		},
	}

	for name, mock := range tests {
		t.Run(name, func(t *testing.T) {
			c := newTestConnector(mock)
			if _, err := c.ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

// emptyResult is a well-formed search response with no entries, which is what a
// directory returns for a base DN the service account cannot read.
func emptyResult() *ldap.SearchResult { return &ldap.SearchResult{Entries: []*ldap.Entry{}} }

// TestPasswordAge_DirectoryReadFailures covers the error paths the policy
// lookups take when the directory refuses or withholds a read. These matter:
// every one of them must surface as an error rather than a silent "no policy",
// which would drop the minimum-age gate for the users it exists to restrict.
func TestPasswordAge_DirectoryReadFailures(t *testing.T) {
	searchErr := fmt.Errorf("ldap: insufficient access rights")

	t.Run("RootDSE read fails", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.BaseDN == "" {
					return nil, searchErr
				}
				return entry(testUserDN, map[string]string{"pwdLastSet": timeToFiletime(time.Now())}), nil
			},
		})
		if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the RootDSE cannot be read")
		}
	})

	t.Run("RootDSE returns no entry", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.BaseDN == "" {
					return emptyResult(), nil
				}
				return entry(testUserDN, map[string]string{"pwdLastSet": timeToFiletime(time.Now())}), nil
			},
		})
		if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the RootDSE returns nothing")
		}
	})

	t.Run("RootDSE has no defaultNamingContext", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if req.BaseDN == "" {
					return entry("", map[string]string{}), nil
				}
				return entry(testUserDN, map[string]string{"pwdLastSet": timeToFiletime(time.Now())}), nil
			},
		})
		if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when defaultNamingContext is empty")
		}
	})

	t.Run("domain head read fails", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				switch req.BaseDN {
				case "":
					return entry("", map[string]string{"defaultNamingContext": testDomainDN}), nil
				case testDomainDN:
					return nil, searchErr
				}
				return entry(testUserDN, map[string]string{"pwdLastSet": timeToFiletime(time.Now())}), nil
			},
		})
		if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the domain head cannot be read")
		}
	})

	t.Run("domain head returns no entry", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				switch req.BaseDN {
				case "":
					return entry("", map[string]string{"defaultNamingContext": testDomainDN}), nil
				case testDomainDN:
					return emptyResult(), nil
				}
				return entry(testUserDN, map[string]string{"pwdLastSet": timeToFiletime(time.Now())}), nil
			},
		})
		if _, err := c.PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the domain head returns nothing")
		}
	})

	t.Run("minPwdAge is not a number", func(t *testing.T) {
		m := &ageMock{
			user:   map[string]string{"pwdLastSet": timeToFiletime(time.Now())},
			domain: map[string]string{"minPwdAge": "not-a-number"},
		}
		if _, err := newTestConnector(m.conn()).PasswordChangeAllowedAt(context.Background(), testUserDN); err == nil {
			t.Error("expected an error parsing a non-numeric minPwdAge")
		}
	})
}

// TestPasswordChangeAllowedAt_ResolveUserDNFails covers the lookup that turns a
// bare account name into a DN.
func TestPasswordChangeAllowedAt_ResolveUserDNFails(t *testing.T) {
	c := newTestConnector(&mockLDAPConn{
		bindFunc:   func(_, _ string) error { return nil },
		searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) { return emptyResult(), nil },
	})
	if _, err := c.PasswordChangeAllowedAt(context.Background(), "jdoe"); err == nil {
		t.Error("expected an error when the account name cannot be resolved to a DN")
	}
}

// TestResolvePasswordPolicy_Failures covers the guidance lookup's error paths.
func TestResolvePasswordPolicy_Failures(t *testing.T) {
	t.Run("user cannot be resolved", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc:   func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) { return emptyResult(), nil },
		})
		if _, err := c.ResolvePasswordPolicy(context.Background(), "jdoe"); err == nil {
			t.Error("expected an error when the account name cannot be resolved")
		}
	})

	t.Run("service bind fails", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return fmt.Errorf("ldap: invalid credentials") },
		})
		if _, err := c.ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the service account cannot bind")
		}
	})

	t.Run("user object read fails", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, fmt.Errorf("ldap: server down")
			},
		})
		if _, err := c.ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the user object cannot be read")
		}
	})

	t.Run("user object not found", func(t *testing.T) {
		c := newTestConnector(&mockLDAPConn{
			bindFunc:   func(_, _ string) error { return nil },
			searchFunc: func(_ *ldap.SearchRequest) (*ldap.SearchResult, error) { return emptyResult(), nil },
		})
		if _, err := c.ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the user object is missing")
		}
	})

	t.Run("minimum length unreadable", func(t *testing.T) {
		m := &ageMock{
			user:   map[string]string{"sAMAccountName": "jdoe"},
			domain: map[string]string{}, // minPwdLength withheld
		}
		if _, err := newTestConnector(m.conn()).ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when no minimum length is available")
		}
	})

	t.Run("complexity lookup fails", func(t *testing.T) {
		calls := 0
		c := newTestConnector(&mockLDAPConn{
			bindFunc: func(_, _ string) error { return nil },
			searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				switch req.BaseDN {
				case testUserDN:
					return entry(testUserDN, map[string]string{"sAMAccountName": "jdoe"}), nil
				case "":
					// Fail the second RootDSE read, i.e. the complexity lookup.
					calls++
					if calls > 1 {
						return nil, fmt.Errorf("ldap: server down")
					}
					return entry("", map[string]string{"defaultNamingContext": testDomainDN}), nil
				}
				return entry(testDomainDN, map[string]string{"minPwdLength": "8"}), nil
			},
		})
		if _, err := c.ResolvePasswordPolicy(context.Background(), testUserDN); err == nil {
			t.Error("expected an error when the complexity lookup fails")
		}
	})

	t.Run("pwdProperties withheld means complexity off", func(t *testing.T) {
		m := &ageMock{
			user:   map[string]string{"sAMAccountName": "jdoe"},
			domain: map[string]string{"minPwdLength": "8"},
		}
		policy, err := newTestConnector(m.conn()).ResolvePasswordPolicy(context.Background(), testUserDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if policy.ComplexityEnabled {
			t.Error("an absent pwdProperties must not be reported as complexity enabled")
		}
	})
}
