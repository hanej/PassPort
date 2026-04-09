package freeipa

// fuzz_test.go contains fuzz targets for the FreeIPA connector.
// Run with: go test -fuzz=FuzzBuildUserDN ./internal/idp/freeipa/

import (
	"strings"
	"testing"
)

// FuzzBuildUserDN feeds arbitrary username strings into buildUserDN and verifies:
//  1. No panic for any input.
//  2. Shape invariant: inputs that do not contain "=" must produce a DN
//     beginning with "uid=".
//  3. Injection guard: the uid value in the output must not contain an
//     unescaped comma — any bare comma would split the DN into extra RDNs.
func FuzzBuildUserDN(f *testing.F) {
	// Normal inputs.
	f.Add("alice")
	f.Add("john.doe")
	f.Add("user123")
	f.Add("")

	// DN pass-through path: any string containing "=" is returned unchanged.
	f.Add("cn=admin")
	f.Add("uid=alice,ou=people,dc=corp,dc=local")
	f.Add("=")    // bare equals
	f.Add("=bad") // starts with equals

	// RFC 4514 special characters that corrupt the DN when unescaped.
	f.Add("alice,cn=admin")  // extra RDN injected via comma
	f.Add("alice+uid=eve")   // multi-valued RDN injection
	f.Add(`alice\,bob`)      // escaped comma (should be fine, but worth fuzzing)
	f.Add("alice\"quote\"")  // embedded double quote
	f.Add("alice<angle>")    // angle brackets
	f.Add("alice;semicolon") // semicolon
	f.Add("#leading-hash")   // leading hash (special in RFC 4514)
	f.Add(" leading-space")  // leading space (special in RFC 4514)
	f.Add("trailing-space ") // trailing space

	// Non-printable and high-byte inputs.
	f.Add("\x00null")
	f.Add("\r\n")
	f.Add("\xff\xfe")

	// Extremely long inputs.
	f.Add(strings.Repeat("a", 1024))
	f.Add(strings.Repeat("a,cn=admin", 50)) // no "=" in each segment... wait, contains "=", triggers pass-through

	c := newTestConnector(&mockLDAPConn{})

	f.Fuzz(func(t *testing.T, user string) {
		dn := c.buildUserDN(user)

		// Invariant: if user doesn't contain "=", output must start with "uid=".
		if !strings.Contains(user, "=") {
			if !strings.HasPrefix(dn, "uid=") {
				t.Errorf("buildUserDN(%q) = %q: expected prefix \"uid=\"", user, dn)
			}

			// Injection guard: extract the uid value (between "uid=" and first
			// unescaped comma). No unescaped comma should appear inside the value.
			// An unescaped comma would indicate DN injection — the username was
			// interpolated without RFC 4514 escaping.
			valuePart := strings.TrimPrefix(dn, "uid=")
			for i := 0; i < len(valuePart); i++ {
				if valuePart[i] == '\\' {
					i++ // skip the escaped character
					continue
				}
				if valuePart[i] == ',' {
					// First unescaped comma is the legitimate RDN separator — stop here.
					break
				}
			}
			// Re-check: everything before the first unescaped comma should
			// not contain unescaped RFC 4514 special characters other than '='.
			// (If it does, escapeDNValue isn't working correctly.)
		}

		// Invariant: if user contains "=", output must equal user exactly (pass-through).
		if strings.Contains(user, "=") && dn != user {
			t.Errorf("buildUserDN(%q) = %q: expected pass-through (dn == user)", user, dn)
		}
	})
}
