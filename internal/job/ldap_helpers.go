package job

import (
	"fmt"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// ExpiringUser represents a user whose password is expiring.
type ExpiringUser struct {
	DN             string
	Username       string
	Email          string
	ExpirationDate time.Time
	DaysRemaining  int
}

// parseWindowsFileTime converts an AD pwdLastSet value (100-nanosecond intervals
// since January 1, 1601) to a Go time.Time.
func parseWindowsFileTime(raw string) (time.Time, error) {
	ft, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing filetime %q: %w", raw, err)
	}
	if ft <= 0 {
		return time.Time{}, fmt.Errorf("invalid filetime: %d", ft)
	}
	// Windows epoch is 1601-01-01, Unix epoch is 1970-01-01.
	// Difference is 11644473600 seconds.
	const epochDiff = 11644473600
	secs := ft/10000000 - epochDiff
	nsecs := (ft % 10000000) * 100
	return time.Unix(secs, nsecs), nil
}

// getADMaxPwdAge reads the maxPwdAge attribute from the AD domain root.
// maxPwdAge is stored as a negative 100-nanosecond interval.
// Returns the duration as a positive value.
func getADMaxPwdAge(conn idp.LDAPConn, baseDN string) (time.Duration, error) {
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"maxPwdAge"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return 0, fmt.Errorf("searching for maxPwdAge: %w", err)
	}
	if len(result.Entries) == 0 {
		return 0, fmt.Errorf("domain root not found: %s", baseDN)
	}
	raw := result.Entries[0].GetAttributeValue("maxPwdAge")
	if raw == "" {
		return 0, fmt.Errorf("maxPwdAge not set on %s", baseDN)
	}
	// maxPwdAge is a negative 100-nanosecond interval
	val, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing maxPwdAge %q: %w", raw, err)
	}
	if val >= 0 {
		return 0, fmt.Errorf("maxPwdAge is non-negative (password never expires): %d", val)
	}
	// Convert to positive nanoseconds
	nsecs := -val * 100
	return time.Duration(nsecs), nil
}

// parseGeneralizedTime parses FreeIPA's krbPasswordExpiration format.
// Common formats: "20260415120000Z" or "20260415120000+0000"
func parseGeneralizedTime(raw string) (time.Time, error) {
	// Try common formats
	for _, layout := range []string{
		"20060102150405Z",
		"20060102150405+0000",
		"20060102150405-0000",
		"20060102150405Z0700",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse generalized time: %q", raw)
}

// searchADExpiringUsers searches AD for users with passwords expiring within the threshold.
func searchADExpiringUsers(conn idp.LDAPConn, baseDN, userSearchBase, emailAttr string, maxPwdAge time.Duration, threshold int) ([]ExpiringUser, error) {
	if userSearchBase == "" {
		userSearchBase = baseDN
	}
	now := time.Now()
	cutoff := now.Add(time.Duration(threshold) * 24 * time.Hour)

	// Search for enabled user accounts with a password set
	filter := "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet>=1))"
	attrs := []string{"dn", "sAMAccountName", "pwdLastSet"}
	if emailAttr != "" {
		attrs = append(attrs, emailAttr)
	}

	searchReq := ldap.NewSearchRequest(
		userSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("AD user search: %w", err)
	}

	var users []ExpiringUser
	for _, entry := range result.Entries {
		pwdLastSetRaw := entry.GetAttributeValue("pwdLastSet")
		if pwdLastSetRaw == "" || pwdLastSetRaw == "0" {
			continue
		}
		pwdLastSet, err := parseWindowsFileTime(pwdLastSetRaw)
		if err != nil {
			continue
		}
		expiresAt := pwdLastSet.Add(maxPwdAge)
		if expiresAt.After(now) && expiresAt.Before(cutoff) {
			daysRemaining := int(time.Until(expiresAt).Hours() / 24)
			users = append(users, ExpiringUser{
				DN:             entry.DN,
				Username:       entry.GetAttributeValue("sAMAccountName"),
				Email:          entry.GetAttributeValue(emailAttr),
				ExpirationDate: expiresAt,
				DaysRemaining:  daysRemaining,
			})
		}
	}
	return users, nil
}

// searchFreeIPAExpiringUsers searches FreeIPA for users with passwords expiring within the threshold.
func searchFreeIPAExpiringUsers(conn idp.LDAPConn, baseDN, userSearchBase, emailAttr string, threshold int) ([]ExpiringUser, error) {
	if userSearchBase == "" {
		userSearchBase = baseDN
	}
	now := time.Now()
	cutoff := now.Add(time.Duration(threshold) * 24 * time.Hour)

	// Search for enabled accounts with krbPasswordExpiration set
	filter := "(&(objectClass=posixAccount)(krbPasswordExpiration=*)(!(nsAccountLock=TRUE)))"
	attrs := []string{"dn", "uid", "krbPasswordExpiration"}
	if emailAttr != "" {
		attrs = append(attrs, emailAttr)
	}

	searchReq := ldap.NewSearchRequest(
		userSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("FreeIPA user search: %w", err)
	}

	var users []ExpiringUser
	for _, entry := range result.Entries {
		expRaw := entry.GetAttributeValue("krbPasswordExpiration")
		if expRaw == "" {
			continue
		}
		expiresAt, err := parseGeneralizedTime(expRaw)
		if err != nil {
			continue
		}
		if expiresAt.After(now) && expiresAt.Before(cutoff) {
			daysRemaining := int(time.Until(expiresAt).Hours() / 24)
			users = append(users, ExpiringUser{
				DN:             entry.DN,
				Username:       entry.GetAttributeValue("uid"),
				Email:          entry.GetAttributeValue(emailAttr),
				ExpirationDate: expiresAt,
				DaysRemaining:  daysRemaining,
			})
		}
	}
	return users, nil
}
