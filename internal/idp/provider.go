package idp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Sentinel errors returned by Provider.SearchUser.
var (
	// ErrNotFound indicates that no matching user was found.
	ErrNotFound = errors.New("user not found")

	// ErrMultipleMatches indicates that more than one user matched.
	ErrMultipleMatches = errors.New("multiple users matched")
)

// ProviderType identifies the type of identity provider.
type ProviderType string

const (
	ProviderTypeAD      ProviderType = "ad"
	ProviderTypeFreeIPA ProviderType = "freeipa"
)

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
	RetryCount             int    `json:"retry_count"`     // default 1
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
}

// Secrets holds the sensitive configuration for an IDP (decrypted from secret_blob).
type Secrets struct {
	ServiceAccountUsername string `json:"service_account_username"`
	ServiceAccountPassword string `json:"service_account_password"`
}

// DefaultLDAPConnector is the production implementation of LDAPConnector.
type DefaultLDAPConnector struct{}

// Connect establishes an LDAP or LDAPS connection to the given endpoint.
func (c *DefaultLDAPConnector) Connect(_ context.Context, endpoint, protocol string, timeout int, tlsSkipVerify bool) (LDAPConn, error) {
	if timeout <= 0 {
		timeout = 10
	}

	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: tlsSkipVerify,
	}

	var conn *ldap.Conn
	var err error

	switch protocol {
	case "ldaps":
		conn, err = ldap.DialURL(
			fmt.Sprintf("ldaps://%s", endpoint),
			ldap.DialWithTLSConfig(tlsCfg),
			ldap.DialWithDialer(dialer),
		)
	case "starttls":
		// Connect plaintext then upgrade with STARTTLS.
		conn, err = ldap.DialURL(
			fmt.Sprintf("ldap://%s", endpoint),
			ldap.DialWithDialer(dialer),
		)
		if err == nil {
			err = conn.StartTLS(tlsCfg)
			if err != nil {
				conn.Close()
				conn = nil
			}
		}
	case "ldap":
		conn, err = ldap.DialURL(
			fmt.Sprintf("ldap://%s", endpoint),
			ldap.DialWithDialer(dialer),
		)
	default:
		return nil, fmt.Errorf("unsupported LDAP protocol: %s", protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to LDAP endpoint %s (%s): %w", endpoint, protocol, err)
	}

	return conn, nil
}
