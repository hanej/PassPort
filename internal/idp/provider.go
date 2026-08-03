package idp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Sentinel errors returned by Provider implementations.
var (
	// ErrNotFound indicates that no matching user was found.
	ErrNotFound = errors.New("user not found")

	// ErrMultipleMatches indicates that more than one user matched.
	ErrMultipleMatches = errors.New("multiple users matched")

	// Authentication and account state errors returned by directory connectors.
	ErrPasswordMustChange = errors.New("user must change password at next logon")
	ErrPasswordExpired    = errors.New("password has expired")
	ErrAccountLocked      = errors.New("account is locked out")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrAccountExpired     = errors.New("account has expired")
	// ErrPasswordPolicy covers every rule AD reports as 0000052D: complexity,
	// history and minimum age are indistinguishable in the response.
	ErrPasswordPolicy = errors.New("password does not meet complexity, history, or minimum age requirements")
)

// ProviderType identifies the type of identity provider.
type ProviderType string

const (
	ProviderTypeAD      ProviderType = "ad"
	ProviderTypeFreeIPA ProviderType = "freeipa"
	// ProviderTypeWebLink is a non-directory provider that simply links out to
	// an external site. It has no LDAP connection and no Provider implementation.
	ProviderTypeWebLink ProviderType = "weblink"
)

// IsDirectory reports whether the provider type is backed by an LDAP directory.
func (t ProviderType) IsDirectory() bool {
	return t == ProviderTypeAD || t == ProviderTypeFreeIPA
}

// idPattern constrains provider slugs. A slug is the identity_providers primary
// key and is interpolated into the uploaded logo filename, so it must stay
// filesystem- and URL-safe.
var idPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// ValidID reports whether s is an acceptable provider slug.
func ValidID(s string) bool {
	return idPattern.MatchString(s)
}

// NormalizeWebLinkURL validates a weblink target URL and returns it, or an
// empty string if it is not an absolute http(s) URL. This blocks scheme-based
// injection such as javascript: or data: URLs.
func NormalizeWebLinkURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return ""
	}
	if u.Host == "" {
		return ""
	}
	return u.String()
}

// Provider is the interface that all identity provider connectors must implement.
type Provider interface {
	// Authenticate verifies user credentials against the directory.
	Authenticate(ctx context.Context, user, password string) error

	// ChangePassword changes the user's password (requires current password).
	ChangePassword(ctx context.Context, user, oldPassword, newPassword string) error

	// ResetPassword sets a new password without requiring the current one (admin operation).
	ResetPassword(ctx context.Context, user, newPassword string) error

	// UnlockAccount unlocks a locked-out user account.
	UnlockAccount(ctx context.Context, user string) error

	// EnableAccount enables a disabled user account.
	EnableAccount(ctx context.Context, user string) error

	// GetUserGroups returns the DNs of groups the user belongs to.
	GetUserGroups(ctx context.Context, user string) ([]string, error)

	// GetGroupMembers returns the DNs of all members of the given group DN.
	GetGroupMembers(ctx context.Context, groupDN string) ([]string, error)

	// TestConnection verifies the service account can connect and bind.
	TestConnection(ctx context.Context) error

	// SearchUser searches for a user by an arbitrary attribute and returns the DN.
	SearchUser(ctx context.Context, attr, value string) (string, error)

	// GetUserAttribute reads a specific attribute from a user DN.
	GetUserAttribute(ctx context.Context, userDN, attr string) (string, error)

	// Type returns the provider type (ad, freeipa).
	Type() ProviderType

	// ID returns the unique identifier for this provider instance.
	ID() string
}

// PasswordAgeClearer is implemented by connectors that can exempt an account from
// the directory's minimum password age. The self-service reset flow needs this
// because it stages a temporary password first, which resets the age clock and
// would otherwise make the user's own change illegal.
type PasswordAgeClearer interface {
	ClearPasswordAge(ctx context.Context, user string) error
}

// PasswordAgePolicy is implemented by connectors that can report the earliest time
// the directory will accept a password change for a user. Connectors that also
// implement PasswordAgeClearer must implement this, since clearing the age disables
// the directory's own check and Passport has to apply the equivalent gate itself.
// The zero time means a change is allowed now.
type PasswordAgePolicy interface {
	PasswordChangeAllowedAt(ctx context.Context, user string) (time.Time, error)
}

// PasswordPolicy describes the directory rules that can be evaluated before a
// password is submitted. A zero MinLength means the length could not be determined.
type PasswordPolicy struct {
	MinLength         int
	ComplexityEnabled bool
	// SamAccountName and DisplayName support Active Directory's complexity rule
	// that a password may contain neither the account name nor a token of the
	// display name.
	SamAccountName string
	DisplayName    string
}

// PasswordPolicyReader is implemented by connectors that can report the password
// rules applying to a specific user, which may differ from the domain default when
// a fine-grained policy applies. Callers must treat an error as "unknown" and fall
// back to their configured behaviour rather than blocking the user.
type PasswordPolicyReader interface {
	ResolvePasswordPolicy(ctx context.Context, user string) (PasswordPolicy, error)
}

// LDAPConnector abstracts LDAP connection creation for testability.
type LDAPConnector interface {
	Connect(ctx context.Context, endpoint, protocol string, timeout int, tlsSkipVerify bool) (LDAPConn, error)
}

// LDAPConn represents an active LDAP connection.
type LDAPConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Modify(req *ldap.ModifyRequest) error
	PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	Close() error
}

// Config holds the non-sensitive configuration for an IDP (parsed from config_json).
type Config struct {
	Endpoint               string `json:"endpoint"`
	Protocol               string `json:"protocol"` // "ldap" or "ldaps"
	BaseDN                 string `json:"base_dn"`
	UserSearchBase         string `json:"user_search_base"`
	GroupSearchBase        string `json:"group_search_base"`
	Timeout                int    `json:"timeout"`         // seconds, default 10
	TLSSkipVerify          bool   `json:"tls_skip_verify"` // skip TLS certificate verification
	PasswordComplexityHint string `json:"password_complexity_hint"`
	SendNotification       bool   `json:"send_notification"`
	NotificationEmailAttr  string `json:"notification_email_attr"`
	// Random password policy for MFA reset. When PasswordLength is 0, defaults are used.
	PasswordAllowUppercase    bool   `json:"password_allow_uppercase"`
	PasswordAllowLowercase    bool   `json:"password_allow_lowercase"`
	PasswordAllowDigits       bool   `json:"password_allow_digits"`
	PasswordAllowSpecialChars bool   `json:"password_allow_special_chars"`
	PasswordSpecialChars      string `json:"password_special_chars"`
	PasswordLength            int    `json:"password_length"`
	// URL is the external target for weblink providers.
	URL string `json:"url,omitempty"`
}

// Secrets holds the sensitive configuration for an IDP (decrypted from secret_blob).
type Secrets struct {
	ServiceAccountUsername string `json:"service_account_username"`
	ServiceAccountPassword string `json:"service_account_password"`
}

// DefaultLDAPConnector is the production implementation of LDAPConnector.
type DefaultLDAPConnector struct{}

// Connect establishes an LDAP connection to the given endpoint string.
// The endpoint may be a comma-separated list; a random one is tried first
// and the rest are tried in order on failure.
func (c *DefaultLDAPConnector) Connect(_ context.Context, endpoint, protocol string, timeout int, tlsSkipVerify bool) (LDAPConn, error) {
	if timeout <= 0 {
		timeout = 10
	}

	endpoints := splitEndpoints(endpoint)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no LDAP endpoint specified")
	}

	// Shuffle so a random endpoint is tried first, providing both load
	// distribution and automatic failover across the list.
	rand.Shuffle(len(endpoints), func(i, j int) { endpoints[i], endpoints[j] = endpoints[j], endpoints[i] })

	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	tlsCfg := &tls.Config{InsecureSkipVerify: tlsSkipVerify}

	var lastErr error
	for _, ep := range endpoints {
		conn, err := dialLDAP(ep, protocol, dialer, tlsCfg)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if len(endpoints) == 1 {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all %d LDAP endpoints failed; last error: %w", len(endpoints), lastErr)
}

// splitEndpoints parses a comma-separated endpoint string, trimming whitespace
// and dropping empty entries.
func splitEndpoints(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dialLDAP opens a single connection to the given endpoint using the specified protocol.
func dialLDAP(endpoint, protocol string, dialer *net.Dialer, tlsCfg *tls.Config) (LDAPConn, error) {
	switch protocol {
	case "ldaps":
		conn, err := ldap.DialURL(
			fmt.Sprintf("ldaps://%s", endpoint),
			ldap.DialWithTLSConfig(tlsCfg),
			ldap.DialWithDialer(dialer),
		)
		if err != nil {
			return nil, fmt.Errorf("connecting to LDAP endpoint %s (%s): %w", endpoint, protocol, err)
		}
		return conn, nil
	case "starttls":
		conn, err := ldap.DialURL(
			fmt.Sprintf("ldap://%s", endpoint),
			ldap.DialWithDialer(dialer),
		)
		if err != nil {
			return nil, fmt.Errorf("connecting to LDAP endpoint %s (%s): %w", endpoint, protocol, err)
		}
		if err = conn.StartTLS(tlsCfg); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("connecting to LDAP endpoint %s (starttls upgrade): %w", endpoint, err)
		}
		return conn, nil
	case "ldap":
		conn, err := ldap.DialURL(
			fmt.Sprintf("ldap://%s", endpoint),
			ldap.DialWithDialer(dialer),
		)
		if err != nil {
			return nil, fmt.Errorf("connecting to LDAP endpoint %s (%s): %w", endpoint, protocol, err)
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported LDAP protocol: %s", protocol)
	}
}
