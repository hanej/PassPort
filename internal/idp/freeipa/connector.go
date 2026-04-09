package freeipa

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// Connector implements idp.Provider for FreeIPA.
type Connector struct {
	id        string
	config    idp.Config
	secrets   idp.Secrets
	connector idp.LDAPConnector
	logger    *slog.Logger
}

// New creates a new FreeIPA connector.
func New(id string, cfg idp.Config, secrets idp.Secrets, connector idp.LDAPConnector, logger *slog.Logger) *Connector {
	return &Connector{
		id:        id,
		config:    cfg,
		secrets:   secrets,
		connector: connector,
		logger:    logger.With("component", "freeipa-connector", "idp_id", id),
	}
}

// Type returns ProviderTypeFreeIPA.
func (c *Connector) Type() idp.ProviderType { return idp.ProviderTypeFreeIPA }

// ID returns the unique identifier for this provider.
func (c *Connector) ID() string { return c.id }

// connect establishes a new LDAP connection using the configured endpoint.
func (c *Connector) connect(ctx context.Context) (idp.LDAPConn, error) {
	return c.connector.Connect(ctx, c.config.Endpoint, c.config.Protocol, c.config.Timeout, c.config.TLSSkipVerify)
}

// bindAsService connects and binds with the service account credentials.
func (c *Connector) bindAsService(ctx context.Context) (idp.LDAPConn, error) {
	c.logger.Debug("binding as service account", "endpoint", c.config.Endpoint)
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to FreeIPA: %w", err)
	}
	if err := conn.Bind(c.secrets.ServiceAccountUsername, c.secrets.ServiceAccountPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("service account bind failed: %w", err)
	}
	c.logger.Debug("service account bind successful")
	return conn, nil
}

// TestConnection verifies that the service account can bind to the directory.
func (c *Connector) TestConnection(ctx context.Context) error {
	c.logger.Debug("testing connection",
		"endpoint", c.config.Endpoint,
		"protocol", c.config.Protocol,
		"tls_skip_verify", c.config.TLSSkipVerify,
	)
	conn, err := c.bindAsService(ctx)
	if err != nil {
		return err
	}
	conn.Close()
	c.logger.Info("test connection successful")
	return nil
}

// Authenticate verifies user credentials by building a DN from the uid and binding.
func (c *Connector) Authenticate(ctx context.Context, user, password string) error {
	c.logger.Debug("authenticating user", "user", user, "endpoint", c.config.Endpoint)

	conn, err := c.connect(ctx)
	if err != nil {
		c.logger.Debug("connection failed during authenticate", "user", user, "error", err)
		return fmt.Errorf("connecting to FreeIPA: %w", err)
	}
	defer conn.Close()

	userDN := c.buildUserDN(user)
	c.logger.Debug("binding as user", "user_dn", userDN)

	if err := conn.Bind(userDN, password); err != nil {
		c.logger.Debug("bind failed during authenticate", "user", user, "user_dn", userDN, "error", err)
		return fmt.Errorf("authentication failed for %q: %w", user, err)
	}

	c.logger.Debug("authentication successful", "user", user)
	return nil
}

// ChangePassword changes the user's password using the LDAP Password Modify
// Extended Operation (RFC 3062). The user binds with their current credentials
// and then issues the password change.
func (c *Connector) ChangePassword(ctx context.Context, user, oldPassword, newPassword string) error {
	c.logger.Debug("changing password", "user", user)
	conn, err := c.connect(ctx)
	if err != nil {
		return fmt.Errorf("connecting to FreeIPA: %w", err)
	}
	defer conn.Close()

	userDN := c.buildUserDN(user)

	// Bind as the user to prove knowledge of the current password.
	if err := conn.Bind(userDN, oldPassword); err != nil {
		return fmt.Errorf("current password verification failed: %w", err)
	}
	c.logger.Debug("old password verified", "user", user)

	// Issue the password modify extended operation.
	passReq := ldap.NewPasswordModifyRequest(userDN, oldPassword, newPassword)
	if _, err := conn.PasswordModify(passReq); err != nil {
		return fmt.Errorf("changing password for %q: %w", user, err)
	}

	c.logger.Debug("password change successful", "user", user)
	c.logger.Info("password changed", "user", user)
	return nil
}

// ResetPassword sets a new password without requiring the current one.
// Binds as the service account and uses the Password Modify Extended Operation.
func (c *Connector) ResetPassword(ctx context.Context, user, newPassword string) error {
	c.logger.Debug("resetting password", "user", user)
	conn, err := c.bindAsService(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	userDN := c.buildUserDN(user)

	passReq := ldap.NewPasswordModifyRequest(userDN, "", newPassword)
	if _, err := conn.PasswordModify(passReq); err != nil {
		return fmt.Errorf("resetting password for %q: %w", user, err)
	}

	c.logger.Debug("password reset successful", "user", user)
	c.logger.Info("password reset", "user", user)
	return nil
}

// UnlockAccount unlocks a locked-out user by setting nsAccountLock to "FALSE"
// and resetting krbLoginFailedCount to "0".
func (c *Connector) UnlockAccount(ctx context.Context, user string) error {
	c.logger.Debug("unlocking account", "user", user)
	userDN := c.buildUserDN(user)

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("nsAccountLock", []string{"FALSE"})
	modReq.Replace("krbLoginFailedCount", []string{"0"})

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("unlocking account %q: %w", userDN, err)
	}

	c.logger.Debug("account unlock successful", "user", user)
	c.logger.Info("account unlocked", "user", user)
	return nil
}

// EnableAccount enables a disabled user by setting nsAccountLock to "FALSE".
func (c *Connector) EnableAccount(ctx context.Context, user string) error {
	c.logger.Debug("enabling account", "user", user)
	userDN := c.buildUserDN(user)

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("nsAccountLock", []string{"FALSE"})

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("enabling account %q: %w", userDN, err)
	}

	c.logger.Debug("account enable successful", "user", user)
	c.logger.Info("account enabled", "user", user)
	return nil
}

// GetUserGroups returns the DNs of all groups the user belongs to.
// In FreeIPA, group membership is stored on the group objects, so we search
// for groups where member equals the user DN.
func (c *Connector) GetUserGroups(ctx context.Context, user string) ([]string, error) {
	c.logger.Debug("getting user groups", "user", user)
	userDN := c.buildUserDN(user)

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	groupBase := c.config.GroupSearchBase
	if groupBase == "" {
		groupBase = c.config.BaseDN
	}

	filter := fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN))
	searchReq := ldap.NewSearchRequest(
		groupBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("searching groups for %q: %w", userDN, err)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		groups = append(groups, entry.DN)
	}
	c.logger.Debug("user groups found", "user", user, "count", len(groups))
	return groups, nil
}

// GetGroupMembers returns the DNs of all members of the given group DN.
func (c *Connector) GetGroupMembers(ctx context.Context, groupDN string) ([]string, error) {
	c.logger.Debug("getting group members", "group_dn", groupDN)
	conn, err := c.bindAsService(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchReq := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"member"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("searching members of %q: %w", groupDN, err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("group not found: %s", groupDN)
	}

	members := result.Entries[0].GetAttributeValues("member")
	c.logger.Debug("group members found", "group_dn", groupDN, "count", len(members))
	return members, nil
}

// SearchUser searches for a user by an arbitrary attribute and returns the DN.
func (c *Connector) SearchUser(ctx context.Context, attr, value string) (string, error) {
	c.logger.Debug("searching for user", "attr", attr, "value", value)
	conn, err := c.bindAsService(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	searchBase := c.config.UserSearchBase
	if searchBase == "" {
		searchBase = c.config.BaseDN
	}

	filter := fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(attr), ldap.EscapeFilter(value))
	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("searching for user (%s=%s): %w", attr, value, err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("user not found: %s=%s", attr, value)
	}

	c.logger.Debug("user found", "dn", result.Entries[0].DN)
	return result.Entries[0].DN, nil
}

// GetUserAttribute reads a specific attribute from a user DN.
func (c *Connector) GetUserAttribute(ctx context.Context, userDN, attr string) (string, error) {
	c.logger.Debug("getting user attribute", "user_dn", userDN, "attr", attr)
	conn, err := c.bindAsService(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{attr},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("reading attribute %q from %q: %w", attr, userDN, err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("user not found: %s", userDN)
	}

	val := result.Entries[0].GetAttributeValue(attr)
	c.logger.Debug("attribute value retrieved", "user_dn", userDN, "attr", attr, "value", val)
	return val, nil
}

// buildUserDN constructs a user DN from a username. If the user string already
// contains "=", it is assumed to be a full DN and returned as-is.
// Otherwise the username is RFC 4514-escaped before being interpolated so that
// special characters (`,` `+` `"` `\` `<` `>` `;`) cannot corrupt the DN.
func (c *Connector) buildUserDN(user string) string {
	if strings.Contains(user, "=") {
		return user
	}
	searchBase := c.config.UserSearchBase
	if searchBase == "" {
		searchBase = c.config.BaseDN
	}
	return fmt.Sprintf("uid=%s,%s", escapeDNValue(user), searchBase)
}

// escapeDNValue escapes a string for use as an attribute value inside an LDAP
// distinguished name, following RFC 4514 section 2.4.
// It is intentionally not exported — callers should use buildUserDN.
func escapeDNValue(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 0 && (c == ' ' || c == '#'):
			// Leading space or number sign must be escaped.
			b.WriteByte('\\')
			b.WriteByte(c)
		case i == len(s)-1 && c == ' ':
			// Trailing space must be escaped.
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>' || c == '\\':
			// RFC 4514 special characters always require escaping.
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			// Non-printable and non-ASCII bytes are hex-escaped.
			fmt.Fprintf(&b, "\\%02x", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
