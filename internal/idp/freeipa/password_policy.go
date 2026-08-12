package freeipa

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// FreeIPA keeps password policies as krbPwdPolicy entries under the realm
// container, e.g. cn=global_policy,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com.
// A user covered by a group policy is bound to it through krbPwdPolicyReference,
// a virtual attribute the 389-ds Class of Service plugin generates on the user
// entry; everyone else falls back to the global policy. This mirrors the way the
// AD connector prefers a fine-grained policy over the domain default.
const (
	policyRefAttr   = "krbPwdPolicyReference"
	globalPolicyCN  = "global_policy"
	costemplateBase = "cn=costemplates,cn=accounts,"
)

// shownCategories is how many character classes the rule checklist lists. MIT
// Kerberos counts five, the fifth being characters outside printable ASCII,
// which is not something the checklist can sensibly ask a user for.
const shownCategories = 4

// maxMinPwdLifeSeconds bounds krbMinPwdLife before it is converted to a
// time.Duration, which overflows past roughly 292 years.
const maxMinPwdLifeSeconds = 100 * 365 * 24 * 60 * 60

// parseGeneralizedTime parses the LDAP generalized time FreeIPA uses for
// krbLastPwdChange and krbPasswordExpiration, e.g. "20260415120000Z".
func parseGeneralizedTime(raw string) (time.Time, error) {
	for _, layout := range []string{
		"20060102150405Z",
		"20060102150405Z0700",
		"20060102150405-0700",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse generalized time: %q", raw)
}

// PasswordChangeAllowedAt reports the earliest time the directory will accept a
// password change for the user, based on the minimum password lifetime that
// actually applies to them. It returns the zero time when a change is allowed now.
//
// Passport enforces this itself because the self-service reset flow stages a
// temporary password through an administrative reset, and FreeIPA exempts a
// password reset by another principal from the minimum lifetime. Without this
// gate a user could cycle through the password history to reuse an old password.
func (c *Connector) PasswordChangeAllowedAt(ctx context.Context, user string) (time.Time, error) {
	conn, err := c.bindAsService(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = conn.Close() }()

	userDN := c.buildUserDN(user)
	entry, err := c.readEntry(conn, userDN, []string{"krbLastPwdChange", "krbPasswordExpiration", policyRefAttr, "memberOf"})
	if err != nil {
		return time.Time{}, err
	}

	// An already-expired password is exempt from the minimum lifetime, because
	// that is precisely when the user has to be able to set a new one.
	if raw := entry.GetAttributeValue("krbPasswordExpiration"); raw != "" {
		if expiresAt, expErr := parseGeneralizedTime(raw); expErr == nil && !expiresAt.After(time.Now()) {
			c.logger.Debug("password age check skipped, password already expired", "user_dn", userDN)
			return time.Time{}, nil
		}
	}

	raw := entry.GetAttributeValue("krbLastPwdChange")
	if raw == "" {
		// No Kerberos password has been set, so there is no age to measure.
		c.logger.Debug("password age check skipped, krbLastPwdChange is unset", "user_dn", userDN)
		return time.Time{}, nil
	}
	changedAt, err := parseGeneralizedTime(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing krbLastPwdChange %q for %q: %w", raw, userDN, err)
	}

	policyDN, err := c.effectivePolicyDN(conn, entry)
	if err != nil {
		return time.Time{}, err
	}
	minLife, err := c.minPasswordLife(conn, policyDN)
	if err != nil {
		return time.Time{}, err
	}
	if minLife <= 0 {
		c.logger.Debug("no minimum password lifetime configured", "user_dn", userDN, "policy", policyDN)
		return time.Time{}, nil
	}

	allowedAt := changedAt.Add(minLife)
	c.logger.Debug("evaluated minimum password lifetime",
		"user_dn", userDN,
		"password_last_set", changedAt,
		"minimum_life", minLife,
		"change_allowed_at", allowedAt,
		"policy", policyDN,
	)
	if time.Now().Before(allowedAt) {
		return allowedAt, nil
	}
	return time.Time{}, nil
}

// ResolvePasswordPolicy returns the password rules that apply to the user, from
// their group policy when one applies and from the global policy otherwise.
//
// Callers should treat an error as "unknown" rather than fatal: the result exists
// to give the user accurate guidance up front, and the directory remains the
// authority on whether a password is acceptable.
func (c *Connector) ResolvePasswordPolicy(ctx context.Context, user string) (idp.PasswordPolicy, error) {
	var policy idp.PasswordPolicy

	conn, err := c.bindAsService(ctx)
	if err != nil {
		return policy, err
	}
	defer func() { _ = conn.Close() }()

	userDN := c.buildUserDN(user)
	userEntry, err := c.readEntry(conn, userDN, []string{"uid", "displayName", policyRefAttr, "memberOf"})
	if err != nil {
		return policy, err
	}
	policy.SamAccountName = userEntry.GetAttributeValue("uid")
	policy.DisplayName = userEntry.GetAttributeValue("displayName")

	policyDN, err := c.effectivePolicyDN(conn, userEntry)
	if err != nil {
		return policy, err
	}
	policyEntry, err := c.readEntry(conn, policyDN, []string{"krbPwdMinLength", "krbPwdMinDiffChars", "ipaPwdUserCheck"})
	if err != nil {
		return policy, err
	}

	raw := policyEntry.GetAttributeValue("krbPwdMinLength")
	if raw == "" {
		// Presenting rules we could not read would be worse than presenting none,
		// so report this as unknown and let the caller fall back.
		return policy, fmt.Errorf("policy %q returned no krbPwdMinLength; check read access to the policy entry", policyDN)
	}
	if policy.MinLength, err = strconv.Atoi(raw); err != nil {
		return policy, fmt.Errorf("parsing krbPwdMinLength %q from %q: %w", raw, policyDN, err)
	}

	// krbPwdMinDiffChars is how many of the four character classes a password must
	// use. FreeIPA makes this a count rather than the on/off switch AD exposes.
	if raw := policyEntry.GetAttributeValue("krbPwdMinDiffChars"); raw != "" {
		classes, convErr := strconv.Atoi(raw)
		if convErr != nil {
			return policy, fmt.Errorf("parsing krbPwdMinDiffChars %q from %q: %w", raw, policyDN, convErr)
		}
		if classes > shownCategories {
			c.logger.Warn("password policy requires more character classes than the rule list shows",
				"policy", policyDN, "required", classes, "shown", shownCategories)
			classes = shownCategories
		}
		if classes > 0 {
			policy.ComplexityEnabled = true
			policy.MinCategories = classes
		}
	}

	// ipaPwdUserCheck rejects a password containing the account name. FreeIPA 4.9
	// added it as a separate switch; older servers simply do not have it.
	if strings.EqualFold(policyEntry.GetAttributeValue("ipaPwdUserCheck"), "TRUE") {
		policy.ComplexityEnabled = true
		policy.ForbidsUserName = true
	}

	c.logger.Debug("resolved password policy",
		"user_dn", userDN, "minimum_length", policy.MinLength,
		"minimum_categories", policy.MinCategories,
		"forbids_user_name", policy.ForbidsUserName, "policy", policyDN)
	return policy, nil
}

// Diagnose reports whether the service account can actually read password
// policies. FreeIPA restricts them to the Password Policy Readers privilege, so
// an otherwise healthy connection can still leave the rule checklist and the
// minimum-age gate silently unavailable.
func (c *Connector) Diagnose(ctx context.Context) []string {
	const grantHint = " Grant the service account the 'Password Policy Readers' privilege to enable password policy detection."

	conn, err := c.bindAsService(ctx)
	if err != nil {
		// The bind failure is the connection test's own result.
		return nil
	}
	defer func() { _ = conn.Close() }()

	realmDN, err := c.realmContainerDN(conn)
	if err != nil {
		return []string{"Could not locate the Kerberos realm container." + grantHint}
	}

	policyDN := "cn=" + globalPolicyCN + "," + realmDN
	entry, err := c.readEntry(conn, policyDN, []string{"krbPwdMinLength"})
	if err != nil {
		return []string{"Could not read the global password policy." + grantHint}
	}
	if entry.GetAttributeValue("krbPwdMinLength") == "" {
		return []string{"The global password policy is readable but its attributes are not." + grantHint}
	}
	return nil
}

// effectivePolicyDN returns the DN of the password policy governing the user.
func (c *Connector) effectivePolicyDN(conn idp.LDAPConn, userEntry *ldap.Entry) (string, error) {
	if dn := userEntry.GetEqualFoldAttributeValue(policyRefAttr); dn != "" {
		return dn, nil
	}
	// krbPwdPolicyReference is only readable with the User Administrators
	// privilege, so derive the group policy from the Class of Service templates
	// when it is absent. Falling straight through to the global policy would
	// quietly describe rules the user is not actually subject to.
	groupDN, err := c.groupPolicyDN(conn, userEntry.GetEqualFoldAttributeValues("memberOf"))
	if err != nil {
		return "", err
	}
	if groupDN != "" {
		return groupDN, nil
	}
	realmDN, err := c.realmContainerDN(conn)
	if err != nil {
		return "", err
	}
	return "cn=" + globalPolicyCN + "," + realmDN, nil
}

// groupPolicyDN returns the group password policy covering the user, which is
// the one with the lowest cospriority among the groups they belong to. It
// returns an empty DN when no group policy applies.
func (c *Connector) groupPolicyDN(conn idp.LDAPConn, memberOf []string) (string, error) {
	if len(memberOf) == 0 {
		return "", nil
	}

	base := costemplateBase + c.config.BaseDN
	searchReq := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=costemplate)",
		[]string{"cn", "cospriority", policyRefAttr},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		// The container is absent when the realm has no group policies at all.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return "", nil
		}
		return "", fmt.Errorf("reading password policy templates under %q: %w", base, err)
	}

	groups := make([]*ldap.DN, 0, len(memberOf))
	for _, raw := range memberOf {
		if parsed, parseErr := ldap.ParseDN(raw); parseErr == nil {
			groups = append(groups, parsed)
		}
	}

	bestDN := ""
	bestPriority := 0
	for _, entry := range result.Entries {
		policyDN := entry.GetEqualFoldAttributeValue(policyRefAttr)
		if policyDN == "" {
			continue
		}
		// The template's cn is the DN of the group it applies to.
		targetDN, parseErr := ldap.ParseDN(entry.GetAttributeValue("cn"))
		if parseErr != nil {
			continue
		}
		matched := false
		for _, group := range groups {
			if group.EqualFold(targetDN) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		// A lower cospriority wins; an unreadable one sorts last.
		priority := math.MaxInt
		if raw := entry.GetAttributeValue("cospriority"); raw != "" {
			if parsed, convErr := strconv.Atoi(raw); convErr == nil {
				priority = parsed
			}
		}
		if bestDN == "" || priority < bestPriority {
			bestDN, bestPriority = policyDN, priority
		}
	}
	return bestDN, nil
}

// realmContainerDN locates the Kerberos realm container rather than assuming the
// realm is the base DN uppercased, which does not hold when the two were
// configured independently.
func (c *Connector) realmContainerDN(conn idp.LDAPConn) (string, error) {
	base := "cn=kerberos," + c.config.BaseDN
	searchReq := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=krbRealmContainer)",
		[]string{"cn"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("reading Kerberos realm container under %q: %w", base, err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no Kerberos realm container under %q", base)
	}
	return result.Entries[0].DN, nil
}

// minPasswordLife reads krbMinPwdLife, which FreeIPA stores in seconds even
// though its CLI takes hours.
func (c *Connector) minPasswordLife(conn idp.LDAPConn, policyDN string) (time.Duration, error) {
	entry, err := c.readEntry(conn, policyDN, []string{"krbMinPwdLife"})
	if err != nil {
		return 0, err
	}
	raw := entry.GetAttributeValue("krbMinPwdLife")
	if raw == "" {
		return 0, nil
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing krbMinPwdLife %q from %q: %w", raw, policyDN, err)
	}
	if seconds <= 0 || seconds > maxMinPwdLifeSeconds {
		return 0, nil
	}
	return time.Duration(seconds) * time.Second, nil
}

// readEntry reads one entry by DN.
func (c *Connector) readEntry(conn idp.LDAPConn, dn string, attrs []string) (*ldap.Entry, error) {
	searchReq := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		attrs,
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", dn, err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("not found: %s", dn)
	}
	return result.Entries[0], nil
}
