//go:build ignore

// Command ad_policy_check verifies, against a live directory, the assumptions the
// self-service reset flow depends on:
//
//  1. Does an administrative Replace of unicodePwd move pwdLastSet?
//  2. Does a service-bound Delete+Add change get blocked by the minimum password age?
//  3. Does clearing pwdLastSet exempt the account from that check?
//  4. Is complexity enforced on an administrative reset?
//  5. Is password history enforced on a service-bound Delete+Add change?
//  6. Is password history enforced on an administrative reset?
//
// It CHANGES THE TARGET ACCOUNT'S PASSWORD several times and consumes password
// history slots, so point it at a disposable test account only. The account is
// left with a printed random password and the "must change at next logon" flag.
//
// Usage, reading the service account straight out of the Passport database so the
// stored credential never has to be exported to plaintext:
//
//	sudo -u passport go run scripts/ad_policy_check.go \
//	  -db /var/lib/passport/passport.db -idp corp-ad \
//	  -user-dn 'CN=Test User,OU=Users,DC=example,DC=com' \
//	  -confirm
//
// Or supplying the credentials directly:
//
//	export AD_BIND_PASSWORD='...'          # never pass this as an argument
//	go run scripts/ad_policy_check.go \
//	  -endpoint dc01.example.com:636 \
//	  -bind-dn 'CN=Passport Service,OU=Users,DC=example,DC=com' \
//	  -user-dn 'CN=Test User,OU=Users,DC=example,DC=com' \
//	  -confirm
//
// Add -insecure if the domain controller uses a certificate this host does not trust.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/idp"
	_ "modernc.org/sqlite"
)

func main() {
	endpoint := flag.String("endpoint", "", "domain controller host:port (LDAPS)")
	bindDN := flag.String("bind-dn", "", "service account DN or UPN (omit when using -db)")
	userDN := flag.String("user-dn", "", "DN of the disposable test account")
	dbPath := flag.String("db", "", "read endpoint and service account from this Passport database")
	idpID := flag.String("idp", "", "IDP slug to read from the database (requires -db)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	readOnly := flag.Bool("read-only", false, "print effective policy and ACL state only; make no changes")
	confirm := flag.Bool("confirm", false, "required: acknowledges the test account's password will be changed")
	flag.Parse()

	bindPW := os.Getenv("AD_BIND_PASSWORD")
	if *dbPath != "" {
		if *idpID == "" {
			fail("-idp is required with -db")
		}
		var tlsSkip bool
		*endpoint, *bindDN, bindPW, tlsSkip = loadFromDB(*dbPath, *idpID)
		*insecure = *insecure || tlsSkip
	}

	switch {
	case *endpoint == "" || *bindDN == "" || *userDN == "":
		fail("-user-dn is required, plus either -db/-idp or -endpoint/-bind-dn")
	case bindPW == "":
		fail("set the AD_BIND_PASSWORD environment variable, or use -db/-idp")
	case !*confirm && !*readOnly:
		fail("refusing to run without -confirm: this rewrites the target account's password")
	}

	conn, err := ldap.DialURL("ldaps://"+*endpoint, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: *insecure,
		ServerName:         strings.Split(*endpoint, ":")[0],
	}))
	if err != nil {
		fail("connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Bind(*bindDN, bindPW); err != nil {
		fail("service bind: %v", err)
	}
	fmt.Printf("connected to %s as %s\n", *endpoint, *bindDN)

	c := &checker{conn: conn, userDN: *userDN}
	c.discover()
	if *readOnly {
		return
	}
	c.run()
	c.summary()
}

type checker struct {
	conn    *ldap.Conn
	userDN  string
	current string            // password the account currently holds
	results map[string]string // question -> answer
	order   []string
}

// ---------------------------------------------------------------- discovery

func (c *checker) discover() {
	section("A. Effective policy")

	root := c.readAttr("", "defaultNamingContext")
	fmt.Printf("  defaultNamingContext : %s\n", root)

	minPwdAge := c.readAttr(root, "minPwdAge")
	fmt.Printf("  minPwdAge            : %s (%s)\n", minPwdAge, interval(minPwdAge))
	fmt.Printf("  minPwdLength         : %s\n", c.readAttr(root, "minPwdLength"))
	fmt.Printf("  pwdHistoryLength     : %s\n", c.readAttr(root, "pwdHistoryLength"))

	props := c.readAttr(root, "pwdProperties")
	complexity := "not set"
	if n, err := strconv.ParseInt(props, 10, 64); err == nil && n&0x1 != 0 {
		complexity = "DOMAIN_PASSWORD_COMPLEX enabled"
	}
	fmt.Printf("  pwdProperties        : %s (%s)\n", props, complexity)

	pso := c.readAttr(c.userDN, "msDS-ResultantPSO")
	if pso == "" {
		fmt.Printf("  msDS-ResultantPSO    : none (domain default applies)\n")
	} else {
		fmt.Printf("  msDS-ResultantPSO    : %s\n", pso)
		fmt.Printf("  PSO minimum age      : %s (%s)\n",
			c.readAttr(pso, "msDS-MinimumPasswordAge"), interval(c.readAttr(pso, "msDS-MinimumPasswordAge")))
		fmt.Printf("  PSO history length   : %s\n", c.readAttr(pso, "msDS-PasswordHistoryLength"))
	}

	// An empty msDS-ResultantPSO is ambiguous: the DC omits a constructed attribute
	// the caller may not read, so "no PSO applies" and "denied" look identical.
	// Enumerating the container distinguishes them.
	c.reportPSOContainer(root, pso)

	pls := c.readAttr(c.userDN, "pwdLastSet")
	fmt.Printf("  user pwdLastSet      : %s (%s)\n", pls, filetime(pls))

	// adminCount=1 means AdminSDHolder rewrites this account's ACL, stripping any
	// delegated reset permission roughly every hour.
	if c.readAttr(c.userDN, "adminCount") == "1" {
		fmt.Printf("  adminCount           : 1 (PROTECTED by AdminSDHolder)\n")
	} else {
		fmt.Printf("  adminCount           : not set\n")
	}

	switch protected, err := c.daclProtected(c.userDN); {
	case err != nil:
		fmt.Printf("  ACL inheritance      : could not read (%v)\n", err)
	case protected:
		fmt.Printf("  ACL inheritance      : DISABLED (OU delegations do not reach this object)\n")
	default:
		fmt.Printf("  ACL inheritance      : enabled\n")
	}
}

// reportPSOContainer says whether fine-grained password policies exist in the
// domain and whether the bound account can read them, which is what makes an empty
// msDS-ResultantPSO trustworthy.
func (c *checker) reportPSOContainer(root, resultantPSO string) {
	container := "CN=Password Settings Container,CN=System," + root
	res, err := c.conn.Search(ldap.NewSearchRequest(
		container, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=msDS-PasswordSettings)",
		[]string{"cn", "msDS-MinimumPasswordAge", "msDS-MinimumPasswordLength",
			"msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
			"msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo"},
		nil,
	))
	switch {
	case err != nil:
		fmt.Printf("  PSOs in domain       : cannot enumerate (%v)\n", err)
		if resultantPSO == "" {
			fmt.Printf("                         an empty msDS-ResultantPSO may mean 'denied', not 'none'\n")
		}
	case len(res.Entries) == 0:
		fmt.Printf("  PSOs in domain       : none defined (domain policy is the only policy)\n")
	default:
		fmt.Printf("  PSOs in domain       : %d\n", len(res.Entries))
		for _, e := range res.Entries {
			age := e.GetAttributeValue("msDS-MinimumPasswordAge")
			fmt.Printf("    %s (precedence %s)\n", e.GetAttributeValue("cn"),
				e.GetAttributeValue("msDS-PasswordSettingsPrecedence"))
			fmt.Printf("      min age %s (%s), min length %s, history %s, complexity %s\n",
				age, interval(age),
				e.GetAttributeValue("msDS-MinimumPasswordLength"),
				e.GetAttributeValue("msDS-PasswordHistoryLength"),
				e.GetAttributeValue("msDS-PasswordComplexityEnabled"))
			for _, applies := range e.GetAttributeValues("msDS-PSOAppliesTo") {
				fmt.Printf("      applies to %s\n", applies)
			}
		}
	}
}

// daclProtected reports whether SE_DACL_PROTECTED is set, i.e. whether the object
// has "include inheritable permissions from this object's parent" turned off.
func (c *checker) daclProtected(dn string) (bool, error) {
	// LDAP_SERVER_SD_FLAGS_OID, requesting the DACL only so no SeSecurityPrivilege
	// is needed: BER SEQUENCE { INTEGER 4 }.
	sdFlags := ldap.NewControlString("1.2.840.113556.1.4.801", true, string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}))

	res, err := c.conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"nTSecurityDescriptor"}, []ldap.Control{sdFlags},
	))
	if err != nil {
		return false, err
	}
	if len(res.Entries) == 0 {
		return false, fmt.Errorf("no entry returned")
	}
	sd := res.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sd) < 4 {
		return false, fmt.Errorf("security descriptor unreadable")
	}
	const seDACLProtected = 0x1000
	return binary.LittleEndian.Uint16(sd[2:4])&seDACLProtected != 0, nil
}

// ---------------------------------------------------------------- the checks

func (c *checker) run() {
	c.results = map[string]string{}

	// --- 1. Does an administrative Replace move pwdLastSet?
	section("B. Administrative reset and pwdLastSet")
	before := c.readAttr(c.userDN, "pwdLastSet")
	p1 := password()
	if err := c.reset(p1); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			fmt.Printf("  the service account may not reset this user.\n")
			fmt.Printf("  check: adminCount above, and whether the reset delegation covers %q\n",
				parentDN(c.userDN))
		}
		fail("initial administrative reset failed, aborting: %v", err)
	}
	c.current = p1
	after := c.readAttr(c.userDN, "pwdLastSet")
	fmt.Printf("  pwdLastSet before    : %s (%s)\n", before, filetime(before))
	fmt.Printf("  pwdLastSet after     : %s (%s)\n", after, filetime(after))
	c.record("admin reset moves pwdLastSet", yesNo(before != after))

	// --- 2. Is a change immediately after that reset blocked by minimum age?
	section("C. Service-bound Delete+Add immediately after the reset")
	p2 := password()
	err := c.change(c.current, p2)
	switch {
	case err == nil:
		c.current = p2
		fmt.Printf("  change succeeded\n")
		c.record("minimum age blocks a change right after a reset", "NO")
		c.record("service account can perform Delete+Add", "YES")
	case isPolicy(err):
		fmt.Printf("  rejected: %v\n", err)
		c.record("minimum age blocks a change right after a reset", "YES (0000052D)")
		// Reaching a policy check at all means the ACL allowed the operation; an
		// access problem would surface as result code 50 instead.
		c.record("service account can perform Delete+Add", "YES")
	default:
		fmt.Printf("  failed for another reason: %v\n", err)
		c.record("minimum age blocks a change right after a reset", "INCONCLUSIVE: "+err.Error())
	}

	// --- 3. Does clearing pwdLastSet lift that block?
	section("D. Same change after clearing pwdLastSet")
	if err := c.clearAge(); err != nil {
		fmt.Printf("  could not write pwdLastSet=0: %v\n", err)
		c.record("service account may clear pwdLastSet", "NO: "+err.Error())
	} else {
		c.record("service account may clear pwdLastSet", "YES")
		p3 := password()
		if err := c.change(c.current, p3); err != nil {
			fmt.Printf("  rejected: %v\n", err)
			c.record("clearing pwdLastSet lifts the minimum age", "NO")
		} else {
			c.current = p3
			fmt.Printf("  change succeeded\n")
			c.record("clearing pwdLastSet lifts the minimum age", "YES")
			fmt.Printf("  pwdLastSet now       : %s (%s)\n",
				c.readAttr(c.userDN, "pwdLastSet"), filetime(c.readAttr(c.userDN, "pwdLastSet")))
		}
	}

	// --- 4. Is complexity enforced on an administrative reset?
	section("E. Administrative reset with a deliberately weak password")
	if err := c.reset("abc"); err != nil {
		fmt.Printf("  rejected: %v\n", err)
		c.record("complexity/length enforced on an admin reset", yesNo(isPolicy(err))+" (0000052D)")
	} else {
		c.current = "abc"
		fmt.Printf("  ACCEPTED - the directory allowed a 3-character password via Replace\n")
		c.record("complexity/length enforced on an admin reset", "NO")
	}

	// --- 5. Is history enforced on a service-bound Delete+Add?
	section("F. Change back to a very recently used password")
	// Clear the age first so a rejection can only mean history, not minimum age.
	_ = c.clearAge()
	if err := c.change(c.current, p1); err != nil {
		fmt.Printf("  rejected: %v\n", err)
		c.record("history enforced on a Delete+Add change", yesNo(isPolicy(err))+" (0000052D)")
	} else {
		c.current = p1
		fmt.Printf("  ACCEPTED - a password from earlier in this run was reused\n")
		c.record("history enforced on a Delete+Add change", "NO")
	}

	// --- 6. Is history enforced on an administrative reset?
	section("G. Administrative reset to that same recently used password")
	if err := c.reset(p1); err != nil {
		fmt.Printf("  rejected: %v\n", err)
		c.record("history enforced on an admin reset", yesNo(isPolicy(err)))
	} else {
		c.current = p1
		fmt.Printf("  ACCEPTED - Replace reused a password that is still in history\n")
		c.record("history enforced on an admin reset", "NO")
	}
}

// ---------------------------------------------------------------- operations

// reset performs an administrative password set: Replace unicodePwd.
func (c *checker) reset(pw string) error {
	req := ldap.NewModifyRequest(c.userDN, nil)
	req.Replace("unicodePwd", []string{string(encodePassword(pw))})
	return c.conn.Modify(req)
}

// change performs a password change: Delete(old) + Add(new), bound as the service
// account rather than as the user.
func (c *checker) change(oldPW, newPW string) error {
	req := ldap.NewModifyRequest(c.userDN, nil)
	req.Delete("unicodePwd", []string{string(encodePassword(oldPW))})
	req.Add("unicodePwd", []string{string(encodePassword(newPW))})
	return c.conn.Modify(req)
}

func (c *checker) clearAge() error {
	req := ldap.NewModifyRequest(c.userDN, nil)
	req.Replace("pwdLastSet", []string{"0"})
	return c.conn.Modify(req)
}

func (c *checker) readAttr(dn, attr string) string {
	scope := ldap.ScopeBaseObject
	res, err := c.conn.Search(ldap.NewSearchRequest(
		dn, scope, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{attr}, nil,
	))
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	return res.Entries[0].GetAttributeValue(attr)
}

// ---------------------------------------------------------------- reporting

func (c *checker) record(question, answer string) {
	if _, seen := c.results[question]; !seen {
		c.order = append(c.order, question)
	}
	c.results[question] = answer
}

func (c *checker) summary() {
	section("Summary")
	for _, q := range c.order {
		fmt.Printf("  %-48s %s\n", q+":", c.results[q])
	}

	final := password()
	if err := c.reset(final); err != nil {
		fmt.Printf("\n  WARNING: could not set a final password: %v\n", err)
		fmt.Printf("  The account may hold an unknown password. Reset it manually.\n")
		return
	}
	if err := c.clearAge(); err != nil {
		fmt.Printf("\n  WARNING: could not set must-change-at-next-logon: %v\n", err)
	}
	fmt.Printf("\n  Test account left with password: %s\n", final)
	fmt.Printf("  and \"user must change password at next logon\" set.\n")
}

// ---------------------------------------------------------------- helpers

// loadFromDB reads an IDP's endpoint and service account out of the Passport
// database using the same master key and decryption path the server uses, so the
// credential never has to be exported to plaintext.
//
// It deliberately avoids internal/db: that package's queries track the current
// schema, while a production database may predate a migration. Selecting only the
// two columns needed keeps this working against any schema version, and query_only
// guarantees the running service's database is never modified.
func loadFromDB(dbPath, idpID string) (endpoint, bindDN, bindPW string, tlsSkipVerify bool) {
	masterKey, err := crypto.LoadMasterKey()
	if err != nil {
		fail("loading master key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(masterKey, 1)
	if err != nil {
		fail("initialising crypto: %v", err)
	}

	database, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		fail("opening %s: %v", dbPath, err)
	}
	defer func() { _ = database.Close() }()

	var secretBlob []byte
	var configJSON string
	err = database.QueryRow(
		`SELECT secret_blob, config_json FROM identity_providers WHERE id = ?`, idpID,
	).Scan(&secretBlob, &configJSON)
	if errors.Is(err, sql.ErrNoRows) {
		fail("no identity provider with id %q", idpID)
	}
	if err != nil {
		fail("reading IDP %q: %v", idpID, err)
	}
	if len(secretBlob) == 0 {
		fail("IDP %q has no stored credentials", idpID)
	}

	plaintext, err := cryptoSvc.Decrypt(secretBlob)
	if err != nil {
		fail("decrypting credentials for %q: %v", idpID, err)
	}
	var secrets idp.Secrets
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		fail("parsing credentials for %q: %v", idpID, err)
	}
	var cfg idp.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		fail("parsing config for %q: %v", idpID, err)
	}
	return cfg.Endpoint, secrets.ServiceAccountUsername, secrets.ServiceAccountPassword, cfg.TLSSkipVerify
}

func parentDN(dn string) string {
	if i := strings.Index(dn, ","); i >= 0 {
		return dn[i+1:]
	}
	return dn
}

// encodePassword renders a password the way AD requires for unicodePwd: wrapped in
// double quotes and encoded as little-endian UTF-16.
func encodePassword(pw string) []byte {
	var buf bytes.Buffer
	for _, u := range utf16.Encode([]rune(`"` + pw + `"`)) {
		buf.WriteByte(byte(u))
		buf.WriteByte(byte(u >> 8))
	}
	return buf.Bytes()
}

func password() string {
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghijkmnpqrstuvwxyz"
		digits  = "23456789"
		special = "!@#$%^&*()-_=+"
	)
	all := upper + lower + digits + special
	out := []byte{pick(upper), pick(lower), pick(digits), pick(special)}
	for len(out) < 24 {
		out = append(out, pick(all))
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			fail("rand: %v", err)
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out)
}

func pick(set string) byte {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		fail("rand: %v", err)
	}
	return set[n.Int64()]
}

// isPolicy reports whether AD rejected the operation with ERROR_PASSWORD_RESTRICTION,
// the single code it uses for complexity, history and minimum age alike.
func isPolicy(err error) bool {
	return err != nil && strings.Contains(err.Error(), "0000052D")
}

// interval renders a negative 100-nanosecond AD duration in human terms.
func interval(raw string) string {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n == 0 {
		return "no minimum"
	}
	return (time.Duration(-n*100) * time.Nanosecond).String()
}

// filetime renders a Windows FILETIME.
func filetime(raw string) string {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return "unreadable"
	}
	if n <= 0 {
		return "must change at next logon"
	}
	return time.Unix(n/1e7-11644473600, 0).UTC().Format(time.RFC3339)
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

func section(title string) { fmt.Printf("\n=== %s ===\n", title) }

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
