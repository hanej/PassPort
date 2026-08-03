package ad

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// filetimeEpochOffset is the number of seconds between the Windows FILETIME
// epoch (1601-01-01 UTC) and the Unix epoch.
const filetimeEpochOffset = 11644473600

// filetimeToTime converts a Windows FILETIME (100-nanosecond intervals since
// 1601-01-01 UTC) to a time.Time.
func filetimeToTime(ft int64) time.Time {
	return time.Unix(ft/1e7-filetimeEpochOffset, (ft%1e7)*100).UTC()
}

// PasswordChangeAllowedAt reports the earliest time the directory will accept a
// password change for the user, based on the minimum password age that actually
// applies to them. It returns the zero time when a change is allowed right now.
//
// Passport enforces this itself because the self-service reset flow stages a
// temporary password and clears pwdLastSet, which disables AD's own minimum-age
// check. Without this gate a user could cycle through the password history to
// reuse an old password.
func (c *Connector) PasswordChangeAllowedAt(ctx context.Context, user string) (time.Time, error) {
	userDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		return time.Time{}, err
	}

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = conn.Close() }()

	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"pwdLastSet", "msDS-ResultantPSO"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading pwdLastSet from %q: %w", userDN, err)
	}
	if len(result.Entries) == 0 {
		return time.Time{}, fmt.Errorf("user not found: %s", userDN)
	}

	raw := result.Entries[0].GetAttributeValue("pwdLastSet")
	pwdLastSet, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing pwdLastSet %q for %q: %w", raw, userDN, err)
	}
	if pwdLastSet <= 0 {
		// 0 means "must change at next logon", which AD exempts from minimum age.
		c.logger.Debug("password age check skipped, pwdLastSet is unset", "user_dn", userDN)
		return time.Time{}, nil
	}

	// A fine-grained password policy, when one applies, overrides the domain default.
	psoDN := result.Entries[0].GetAttributeValue("msDS-ResultantPSO")
	minAge, err := c.minPasswordAge(conn, psoDN)
	if err != nil {
		return time.Time{}, err
	}
	if minAge <= 0 {
		c.logger.Debug("no minimum password age configured", "user_dn", userDN)
		return time.Time{}, nil
	}

	changedAt := filetimeToTime(pwdLastSet)
	allowedAt := changedAt.Add(minAge)
	c.logger.Debug("evaluated minimum password age",
		"user_dn", userDN,
		"password_last_set", changedAt,
		"minimum_age", minAge,
		"change_allowed_at", allowedAt,
		"pso", psoDN,
	)
	if time.Now().Before(allowedAt) {
		return allowedAt, nil
	}
	return time.Time{}, nil
}

// minPasswordAge reads the minimum password age that applies to a user, from the
// given fine-grained policy when psoDN is set and from the domain head otherwise.
// AD stores both as a negative count of 100-nanosecond intervals.
func (c *Connector) minPasswordAge(conn idp.LDAPConn, psoDN string) (time.Duration, error) {
	raw, attr, err := c.resultantPolicyValue(conn, psoDN, "msDS-MinimumPasswordAge", "minPwdAge")
	if err != nil {
		return 0, err
	}
	if raw == "" {
		// A PSO that resolved but yields nothing means the attribute was withheld,
		// not that the policy is absent. Treating that as "no minimum age" would
		// silently drop the check for exactly the users a PSO exists to restrict.
		if psoDN != "" {
			return 0, fmt.Errorf("PSO %q returned no %s; check read access to the Password Settings Container", psoDN, attr)
		}
		return 0, nil
	}
	interval, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s %q: %w", attr, raw, err)
	}
	// Guard the negation and the ns conversion against overflow on absurd values.
	if interval >= 0 || interval < -(1<<52) {
		return 0, nil
	}
	return time.Duration(-interval * 100), nil
}

// ResolvePasswordPolicy returns the password rules that apply to the user, from
// their fine-grained policy when one applies and from the domain otherwise.
//
// Callers should treat an error as "unknown" rather than fatal: the result exists
// to give the user accurate guidance up front, and the directory remains the
// authority on whether a password is acceptable.
func (c *Connector) ResolvePasswordPolicy(ctx context.Context, user string) (idp.PasswordPolicy, error) {
	var policy idp.PasswordPolicy

	userDN, err := c.resolveUserDN(ctx, user)
	if err != nil {
		return policy, err
	}

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return policy, err
	}
	defer func() { _ = conn.Close() }()

	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"msDS-ResultantPSO", "sAMAccountName", "displayName"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return policy, fmt.Errorf("reading password policy attributes from %q: %w", userDN, err)
	}
	if len(result.Entries) == 0 {
		return policy, fmt.Errorf("user not found: %s", userDN)
	}
	entry := result.Entries[0]
	policy.SamAccountName = entry.GetAttributeValue("sAMAccountName")
	policy.DisplayName = entry.GetAttributeValue("displayName")

	psoDN := entry.GetAttributeValue("msDS-ResultantPSO")
	if policy.MinLength, err = c.minPasswordLength(conn, psoDN, userDN); err != nil {
		return policy, err
	}
	if policy.ComplexityEnabled, err = c.complexityEnabled(conn, psoDN); err != nil {
		return policy, err
	}

	c.logger.Debug("resolved password policy",
		"user_dn", userDN, "minimum_length", policy.MinLength,
		"complexity", policy.ComplexityEnabled, "pso", psoDN)
	return policy, nil
}

func (c *Connector) minPasswordLength(conn idp.LDAPConn, psoDN, userDN string) (int, error) {
	raw, attr, err := c.resultantPolicyValue(conn, psoDN, "msDS-MinimumPasswordLength", "minPwdLength")
	if err != nil {
		return 0, err
	}
	if raw == "" {
		return 0, fmt.Errorf("no %s available for %q", attr, userDN)
	}
	length, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parsing %s %q: %w", attr, raw, err)
	}
	return length, nil
}

// complexityEnabled reads the complexity switch, which a PSO exposes as a boolean
// and the domain head as bit 0 of pwdProperties (DOMAIN_PASSWORD_COMPLEX).
func (c *Connector) complexityEnabled(conn idp.LDAPConn, psoDN string) (bool, error) {
	raw, attr, err := c.resultantPolicyValue(conn, psoDN, "msDS-PasswordComplexityEnabled", "pwdProperties")
	if err != nil {
		return false, err
	}
	if psoDN != "" {
		return strings.EqualFold(raw, "TRUE"), nil
	}
	if raw == "" {
		return false, nil
	}
	props, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, fmt.Errorf("parsing %s %q: %w", attr, raw, err)
	}
	return props&0x1 != 0, nil
}

// resultantPolicyValue reads one password-policy attribute, preferring the given
// fine-grained policy and falling back to the domain head when psoDN is empty.
// It returns the raw value and the attribute name it was read from.
func (c *Connector) resultantPolicyValue(conn idp.LDAPConn, psoDN, psoAttr, domainAttr string) (string, string, error) {
	base, attr := psoDN, psoAttr
	if base == "" {
		var err error
		if base, err = c.defaultNamingContext(conn); err != nil {
			return "", domainAttr, err
		}
		attr = domainAttr
	}

	searchReq := ldap.NewSearchRequest(
		base,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{attr},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return "", attr, fmt.Errorf("reading %s from %q: %w", attr, base, err)
	}
	if len(result.Entries) == 0 {
		return "", attr, fmt.Errorf("reading %s: %q not found", attr, base)
	}
	return result.Entries[0].GetAttributeValue(attr), attr, nil
}

// defaultNamingContext reads the domain head DN from the RootDSE rather than
// assuming the configured base DN is the domain itself.
func (c *Connector) defaultNamingContext(conn idp.LDAPConn) (string, error) {
	searchReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("reading RootDSE: %w", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("reading RootDSE: no entry returned")
	}
	dn := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if dn == "" {
		return "", fmt.Errorf("reading RootDSE: defaultNamingContext is empty")
	}
	return dn, nil
}
