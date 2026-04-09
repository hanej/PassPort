package job

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// ReportUser represents a user entry in a password report.
type ReportUser struct {
	DN              string
	DisplayName     string
	AccountName     string
	PasswordLastSet time.Time
	PasswordExpires time.Time
	DaysRemaining   int        // negative = already expired
	LastLogon       *time.Time // nil if unavailable
}

// compiledReportFilter is a pre-compiled exclusion filter.
type compiledReportFilter struct {
	attribute string
	regex     *regexp.Regexp
}

// filterReportUsers removes users matching any exclusion filter.
func filterReportUsers(conn idp.LDAPConn, users []ReportUser, filters []compiledReportFilter, logger *slog.Logger) []ReportUser {
	var result []ReportUser
	for _, user := range users {
		excluded := false
		for _, cf := range filters {
			attrVal := ""
			if cf.attribute == "dn" || cf.attribute == "distinguishedName" {
				attrVal = user.DN
			} else {
				val, err := readUserAttribute(conn, user.DN, cf.attribute)
				if err != nil {
					continue
				}
				attrVal = val
			}
			if cf.regex.MatchString(attrVal) {
				logger.Debug("report user excluded by filter", "username", user.AccountName, "attribute", cf.attribute)
				excluded = true
				break
			}
		}
		if !excluded {
			result = append(result, user)
		}
	}
	return result
}

// searchADReportUsers searches AD for users and splits them into soon-to-expire and expired lists.
// When excludeDisabled is true, accounts with userAccountControl bit 0x0002 set are excluded via
// LDAP's native bitwise extensible match.
func searchADReportUsers(conn idp.LDAPConn, baseDN, userSearchBase string, maxPwdAge time.Duration, threshold int, excludeDisabled bool) (soonToExpire, expired []ReportUser, err error) {
	if userSearchBase == "" {
		userSearchBase = baseDN
	}
	now := time.Now()
	cutoff := now.Add(time.Duration(threshold) * 24 * time.Hour)

	filter := "(&(objectClass=user)(objectCategory=person)(pwdLastSet>=1))"
	if excludeDisabled {
		filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet>=1))"
	}
	attrs := []string{"sAMAccountName", "displayName", "givenName", "sn", "pwdLastSet", "lastLogonTimestamp"}

	searchReq := ldap.NewSearchRequest(
		userSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, nil, fmt.Errorf("AD report user search: %w", err)
	}

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

		displayName := entry.GetAttributeValue("displayName")
		if displayName == "" {
			gn := entry.GetAttributeValue("givenName")
			sn := entry.GetAttributeValue("sn")
			displayName = strings.TrimSpace(gn + " " + sn)
		}

		var lastLogon *time.Time
		if raw := entry.GetAttributeValue("lastLogonTimestamp"); raw != "" && raw != "0" {
			if t, err := parseWindowsFileTime(raw); err == nil {
				lastLogon = &t
			}
		}

		user := ReportUser{
			DN:              entry.DN,
			DisplayName:     displayName,
			AccountName:     entry.GetAttributeValue("sAMAccountName"),
			PasswordLastSet: pwdLastSet,
			PasswordExpires: expiresAt,
			DaysRemaining:   int(time.Until(expiresAt).Hours() / 24),
			LastLogon:       lastLogon,
		}

		if expiresAt.Before(now) || expiresAt.Equal(now) {
			expired = append(expired, user)
		} else if expiresAt.Before(cutoff) || expiresAt.Equal(cutoff) {
			soonToExpire = append(soonToExpire, user)
		}
	}
	return soonToExpire, expired, nil
}

// searchFreeIPAReportUsers searches FreeIPA for users and splits them into soon-to-expire and expired lists.
// objectClass=inetOrgPerson ensures we only match real user accounts and not service principals.
// Disabled accounts can be excluded via a UI exclusion filter on nsAccountLock=TRUE.
func searchFreeIPAReportUsers(conn idp.LDAPConn, baseDN, userSearchBase string, threshold int) (soonToExpire, expired []ReportUser, err error) {
	if userSearchBase == "" {
		userSearchBase = baseDN
	}
	now := time.Now()
	cutoff := now.Add(time.Duration(threshold) * 24 * time.Hour)

	// objectClass=inetOrgPerson narrows to real user accounts (not service principals).
	filter := "(&(objectClass=inetOrgPerson)(objectClass=posixAccount)(krbPasswordExpiration=*))"
	attrs := []string{"uid", "cn", "givenName", "sn", "krbPasswordExpiration", "krbLastPwdChange", "krbLastSuccessfulAuth", "nsAccountLock"}

	searchReq := ldap.NewSearchRequest(
		userSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, nil, fmt.Errorf("FreeIPA report user search: %w", err)
	}

	for _, entry := range result.Entries {
		expRaw := entry.GetAttributeValue("krbPasswordExpiration")
		if expRaw == "" {
			continue
		}
		expiresAt, err := parseGeneralizedTime(expRaw)
		if err != nil {
			continue
		}

		displayName := entry.GetAttributeValue("cn")
		if displayName == "" {
			gn := entry.GetAttributeValue("givenName")
			sn := entry.GetAttributeValue("sn")
			displayName = strings.TrimSpace(gn + " " + sn)
		}

		var pwdLastSet time.Time
		if raw := entry.GetAttributeValue("krbLastPwdChange"); raw != "" {
			if t, err := parseGeneralizedTime(raw); err == nil {
				pwdLastSet = t
			}
		}

		var lastLogon *time.Time
		if raw := entry.GetAttributeValue("krbLastSuccessfulAuth"); raw != "" {
			if t, err := parseGeneralizedTime(raw); err == nil {
				lastLogon = &t
			}
		}

		user := ReportUser{
			DN:              entry.DN,
			DisplayName:     displayName,
			AccountName:     entry.GetAttributeValue("uid"),
			PasswordLastSet: pwdLastSet,
			PasswordExpires: expiresAt,
			DaysRemaining:   int(time.Until(expiresAt).Hours() / 24),
			LastLogon:       lastLogon,
		}

		if expiresAt.Before(now) || expiresAt.Equal(now) {
			expired = append(expired, user)
		} else if expiresAt.Before(cutoff) || expiresAt.Equal(cutoff) {
			soonToExpire = append(soonToExpire, user)
		}
	}
	return soonToExpire, expired, nil
}
