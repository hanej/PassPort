package ad

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// Connector implements idp.Provider for Active Directory.
type Connector struct {
	id        string
	config    idp.Config
	secrets   idp.Secrets
	connector idp.LDAPConnector
	logger    *slog.Logger
}

// New creates a new Active Directory connector.
func New(id string, cfg idp.Config, secrets idp.Secrets, connector idp.LDAPConnector, logger *slog.Logger) *Connector {
	return &Connector{
		id:        id,
		config:    cfg,
		secrets:   secrets,
		connector: connector,
		logger:    logger.With("component", "ad-connector", "idp_id", id),
	}
}

// Type returns ProviderTypeAD.
func (c *Connector) Type() idp.ProviderType { return idp.ProviderTypeAD }

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
		return nil, fmt.Errorf("connecting to AD: %w", err)
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

// Authenticate verifies user credentials by attempting a bind.
// The user parameter can be a bare username, UPN (user@domain), or a DN.
// Bare usernames are resolved to a DN via the service account before binding.
func (c *Connector) Authenticate(ctx context.Context, user, password string) error {
	c.logger.Debug("authenticating user", "user", user, "endpoint", c.config.Endpoint)

	// Resolve bare usernames to a DN so AD accepts the bind.
	bindDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		c.logger.Debug("failed to resolve user DN for auth", "user", user, "error", err)
		return fmt.Errorf("authentication failed for %q: could not resolve user: %w", user, err)
	}
	c.logger.Debug("resolved bind DN", "user", user, "bind_dn", bindDN)

	conn, err := c.connect(ctx)
	if err != nil {
		c.logger.Debug("connection failed during authenticate", "user", user, "error", err)
		return fmt.Errorf("connecting to AD: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(bindDN, password); err != nil {
		c.logger.Debug("bind failed during authenticate", "user", user, "bind_dn", bindDN, "error", err)
		return fmt.Errorf("authentication failed for %q: %w", user, err)
	}

	c.logger.Debug("authentication successful", "user", user, "bind_dn", bindDN)
	return nil
}

// ChangePassword changes the user's password using the user's own credentials.
// It resolves the user DN via the service account, then binds as the user and
// issues a Delete+Add on unicodePwd. This pattern causes AD to enforce the full
// password policy (complexity, history, minimum age) as a user self-change.
func (c *Connector) ChangePassword(ctx context.Context, user, oldPassword, newPassword string) error {
	c.logger.Debug("changing password", "user", user)

	// Resolve the user's DN via service account (search only).
	userDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		return err
	}

	// Open a connection and bind as the user.
	conn, err := c.connect(ctx)
	if err != nil {
		return fmt.Errorf("connecting to AD: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(userDN, oldPassword); err != nil {
		return fmt.Errorf("current password verification failed: %w", err)
	}
	c.logger.Debug("user bind successful for password change", "user_dn", userDN)

	// Delete+Add while bound as the user forces AD to apply the full password policy.
	// A Replace operation (even with a service account bind) bypasses history and min age.
	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Delete("unicodePwd", []string{string(EncodePassword(oldPassword))})
	modReq.Add("unicodePwd", []string{string(EncodePassword(newPassword))})

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("changing password for %q: %w", userDN, err)
	}
	c.logger.Debug("password change successful", "user", user)
	c.logger.Info("password changed", "user", user)
	return nil
}

// ResetPassword sets a new password without requiring the current one.
// Binds as the service account and modifies the unicodePwd attribute.
func (c *Connector) ResetPassword(ctx context.Context, user, newPassword string) error {
	c.logger.Debug("resetting password", "user", user)
	userDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		return err
	}
	c.logger.Debug("resolved user DN for reset", "user_dn", userDN)

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("unicodePwd", []string{string(EncodePassword(newPassword))})

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("resetting password for %q: %w", userDN, err)
	}
	c.logger.Debug("password reset successful", "user", user)
	c.logger.Info("password reset", "user", user)
	return nil
}

// UnlockAccount unlocks a locked-out user by setting lockoutTime to "0".
func (c *Connector) UnlockAccount(ctx context.Context, user string) error {
	c.logger.Debug("unlocking account", "user", user)
	userDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		return err
	}
	c.logger.Debug("resolved user DN for unlock", "user_dn", userDN)

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("lockoutTime", []string{"0"})

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("unlocking account %q: %w", userDN, err)
	}
	c.logger.Debug("account unlock successful", "user", user)
	c.logger.Info("account unlocked", "user", user)
	return nil
}

// EnableAccount enables a disabled user by clearing the UF_ACCOUNTDISABLE bit (0x0002)
// in the userAccountControl attribute.
func (c *Connector) EnableAccount(ctx context.Context, user string) error {
	c.logger.Debug("enabling account", "user", user)
	userDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		return err
	}

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Read current userAccountControl.
	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"userAccountControl"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("reading userAccountControl for %q: %w", userDN, err)
	}
	if len(result.Entries) == 0 {
		return fmt.Errorf("user not found: %s", userDN)
	}

	uacStr := result.Entries[0].GetAttributeValue("userAccountControl")
	uac, err := strconv.Atoi(uacStr)
	if err != nil {
		return fmt.Errorf("parsing userAccountControl %q: %w", uacStr, err)
	}
	c.logger.Debug("current userAccountControl", "user_dn", userDN, "uac", uac)

	// Clear the UF_ACCOUNTDISABLE bit (bit 1, value 0x0002).
	const ufAccountDisable = 0x0002
	newUAC := uac &^ ufAccountDisable

	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("userAccountControl", []string{strconv.Itoa(newUAC)})

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("enabling account %q: %w", userDN, err)
	}
	c.logger.Debug("account enable successful", "user", user, "new_uac", newUAC)
	c.logger.Info("account enabled", "user", user)
	return nil
}

// GetUserGroups returns the DNs of all groups the user is a member of.
func (c *Connector) GetUserGroups(ctx context.Context, user string) ([]string, error) {
	c.logger.Debug("getting user groups", "user", user)
	userDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		return nil, err
	}

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"memberOf"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("searching groups for %q: %w", userDN, err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %s", userDN)
	}

	groups := result.Entries[0].GetAttributeValues("memberOf")
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
	c.logger.Debug("LDAP search",
		"search_base", searchBase,
		"filter", filter,
		"scope", "subtree",
	)

	searchReq := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("searching for user (%s=%s) in %s: %w", attr, value, searchBase, err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("user not found: %s=%s in base %s", attr, value, searchBase)
	}
	if len(result.Entries) > 1 {
		return "", idp.ErrMultipleMatches
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

// resolveUserDN resolves a user identifier to a DN. If the user string already
// looks like a DN (contains "="), it is returned as-is. Otherwise, a search
// is performed using sAMAccountName.
func (c *Connector) resolveUserDN(ctx context.Context, user string) (string, error) {
	c.logger.Debug("resolving user DN", "user", user)
	if strings.Contains(user, "=") {
		c.logger.Debug("user is already a DN", "dn", user)
		return user, nil
	}
	// Strip @domain for UPN-style identifiers.
	username := user
	if idx := strings.Index(user, "@"); idx > 0 {
		username = user[:idx]
	}
	c.logger.Debug("searching by sAMAccountName", "username", username)
	return c.SearchUser(ctx, "sAMAccountName", username)
}
