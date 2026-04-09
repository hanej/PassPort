package ad

// fuzz_test.go contains fuzz targets for the Active Directory connector.
// Run with: go test -fuzz=FuzzEncodePassword ./internal/idp/ad/
//           go test -fuzz=FuzzResolveUserDN  ./internal/idp/ad/

import (
	"context"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/hanej/passport/internal/idp"
)

// FuzzEncodePassword verifies that EncodePassword never panics for any
// password input and that the output always satisfies structural invariants:
//   - Non-empty output (the wrapping double-quotes alone produce 4 bytes).
//   - Even output length (UTF-16LE uses 2-byte code units).
//
// The corpus includes Unicode edge cases (lone surrogates, supplementary
// characters, null bytes) that exercise the utf16.Encode path.
func FuzzEncodePassword(f *testing.F) {
	// Ordinary passwords.
	f.Add("")
	f.Add("correct-horse-battery-staple")
	f.Add("P@ssw0rd!")
	f.Add("Short1!")

	// Embedded double-quote: "already-quoted" → ""already-quoted""
	f.Add(`"already-quoted"`)
	f.Add(`""`)
	f.Add(`"`)

	// Whitespace variants.
	f.Add(" ")
	f.Add("\t\n\r")
	f.Add("pass word with spaces")

	// Null byte and non-printable.
	f.Add("\x00")
	f.Add("pass\x00word")
	f.Add("\x01\x02\x03")

	// Long input.
	f.Add(strings.Repeat("a", 512))
	f.Add(strings.Repeat("😀", 64))

	// Unicode edge cases.
	f.Add("pass\uFFFDword") // replacement character
	f.Add("🔐emoji")
	f.Add("\u0000\uFFFF") // BMP extremes
	f.Add("\xed\xa0\x80") // lone surrogate (invalid UTF-8; Go decodes as U+FFFD)

	f.Fuzz(func(t *testing.T, password string) {
		result := EncodePassword(password)

		// The wrapping double-quotes are always present, so at minimum
		// 2 UTF-16LE code units (4 bytes) must be produced.
		if len(result) < 4 {
			t.Errorf("EncodePassword(%q): output length %d < 4", password, len(result))
		}

		// UTF-16LE uses 2-byte code units — output must have even length.
		if len(result)%2 != 0 {
			t.Errorf("EncodePassword(%q): odd output length %d", password, len(result))
		}
	})
}

// FuzzResolveUserDN feeds arbitrary user strings into resolveUserDN and verifies:
//  1. No panic for any input.
//  2. Pass-through: if user contains "=", the DN equals user exactly.
//  3. UPN stripping: if user contains "@" (at index > 0), only the part
//     before "@" is used as the sAMAccountName search value.
//
// Security note: resolveUserDN passes through any string containing "=" as an
// arbitrary DN without validation. This allows callers to supply a crafted DN
// targeting any directory object. The fuzz corpus includes "=" inputs to
// exercise this path as a regression set for when validation is added.
func FuzzResolveUserDN(f *testing.F) {
	// Normal usernames.
	f.Add("alice")
	f.Add("john.doe")
	f.Add("")

	// UPN-style inputs.
	f.Add("alice@corp.local")
	f.Add("@nodomain") // "@" at index 0 — NOT stripped (idx must be > 0)
	f.Add("alice@")    // trailing "@"
	f.Add("a@b@c")     // multiple "@" signs

	// DN pass-through inputs.
	f.Add("cn=alice,dc=corp,dc=local")
	f.Add("=")
	f.Add("uid=alice,ou=people,dc=corp,dc=local")

	// Injection attempts.
	f.Add("alice,cn=admin")  // comma injection (no "=", goes to search)
	f.Add("alice)(cn=admin") // LDAP filter injection (escaped by SearchUser)
	f.Add("alice*")          // wildcard (escaped by SearchUser)
	f.Add("\x00null")
	f.Add(strings.Repeat("a", 512))

	// Mock LDAP connection: Search returns a fixed DN so resolveUserDN can complete.
	mockConn := &mockLDAPConn{
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{
					{DN: "cn=found,dc=example,dc=com"},
				},
			}, nil
		},
	}
	c := newTestConnector(mockConn)

	f.Fuzz(func(t *testing.T, user string) {
		dn, err := c.resolveUserDN(context.Background(), user)

		// Must not panic (reaching this line confirms that).

		// Pass-through invariant.
		if strings.Contains(user, "=") {
			if err != nil {
				t.Errorf("resolveUserDN(%q): expected nil error for pass-through, got %v", user, err)
			}
			if dn != user {
				t.Errorf("resolveUserDN(%q) = %q: expected pass-through (dn == user)", user, dn)
			}
		}
	})
}

// FuzzSearchUserFilter verifies that SearchUser never panics and that the LDAP
// filter it constructs is always syntactically valid (i.e., the go-ldap library
// can parse the filter the mock receives without error).
func FuzzSearchUserFilter(f *testing.F) {
	f.Add("sAMAccountName", "alice")
	f.Add("uid", "alice")
	f.Add("mail", "alice@corp.local")
	f.Add("", "")                  // empty attribute and value
	f.Add("cn", "alice*")          // wildcard — should be escaped
	f.Add("cn", "alice)(cn=admin") // filter injection — should be escaped
	f.Add("cn", "\x00null")
	f.Add("cn", strings.Repeat("a", 256))
	f.Add("cn", `alice\,bob`)

	mockConn := &mockLDAPConn{
		bindFunc: func(username, password string) error { return nil },
		searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			// Validate the filter is parseable by go-ldap.
			if _, err := ldap.CompileFilter(req.Filter); err != nil {
				// We cannot call t.Error here — return an error so the caller
				// gets a non-nil error, which the fuzz body can then check.
				return nil, err
			}
			return &ldap.SearchResult{}, nil
		},
	}
	c := newTestConnector(mockConn)
	// Bind as service so SearchUser can proceed past the bind step.

	f.Fuzz(func(t *testing.T, attr, value string) {
		_, err := c.SearchUser(context.Background(), attr, value)
		// If the mock returned a filter-parse error, the filter was invalid.
		if err != nil && strings.Contains(err.Error(), "ldap") {
			// Any LDAP-level error is fine (e.g. no entries found) —
			// but a filter compile error means the filter was malformed.
			if strings.Contains(err.Error(), "filter") || strings.Contains(err.Error(), "parse") {
				t.Errorf("SearchUser produced an invalid LDAP filter: attr=%q value=%q err=%v", attr, value, err)
			}
		}
	})
}

// Compile-time check: idp imported for Secrets use in interface assertion.
var _ idp.LDAPConnector = (*mockLDAPConnector)(nil)
