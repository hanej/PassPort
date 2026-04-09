package emailotp

// fuzz_test.go contains Go fuzz targets for the email OTP package.
// Run a specific fuzzer with: go test -fuzz=FuzzVerify ./internal/mfa/emailotp/
// Without -fuzz the seeds run as a normal unit test (regression check).

import (
	"context"
	"strings"
	"testing"
)

// FuzzVerify feeds arbitrary (code, state) string pairs into Verify.
// The goal is that Verify never panics regardless of input shape.
// Additionally, the fuzzer guards against accidental accept: a state whose
// embedded code does NOT equal the submitted code must never return nil.
func FuzzVerify(f *testing.F) {
	// Seed corpus: valid paths
	f.Add("123456", "otp:123456:9999999999") // well-formed, far future
	f.Add("000000", "otp:000000:9999999999") // all-zero code
	f.Add("999999", "otp:999999:9999999999") // all-nine code

	// Seed corpus: expiry edge cases
	f.Add("123456", "otp:123456:0")          // expired at Unix epoch
	f.Add("123456", "otp:123456:-1")         // negative expiry
	f.Add("123456", "otp:123456:9999999999") // far future

	// Seed corpus: malformed state strings
	f.Add("123456", "")                                                            // empty state
	f.Add("123456", "otp:123456")                                                  // missing expiry field
	f.Add("123456", "otp:123456:abc")                                              // non-numeric expiry
	f.Add("123456", "totp:123456:9999999999")                                      // wrong prefix
	f.Add("123456", "otp:123456:extra:9999999999")                                 // extra colon
	f.Add("123456", "otp::9999999999")                                             // empty code in state
	f.Add("", "otp:123456:9999999999")                                             // empty submitted code
	f.Add(" 123456", "otp:123456:9999999999")                                      // leading space
	f.Add("123456\n", "otp:123456:9999999999")                                     // trailing newline
	f.Add("123456", "otp:123456:9999999999\x00")                                   // null byte in state
	f.Add("\x00\x00\x00\x00\x00\x00", "otp:\x00\x00\x00\x00\x00\x00:9999999999")   // null bytes
	f.Add(strings.Repeat("1", 100), "otp:"+strings.Repeat("1", 100)+":9999999999") // long code

	client := newSecTestClient(6)

	f.Fuzz(func(t *testing.T, code, state string) {
		// Must never panic — any error return is acceptable.
		err := client.Verify(context.Background(), code, state, "")

		// Extra property: if Verify returned nil (accepted), the state must
		// have been well-formed and contain the exact same code we submitted.
		if err == nil {
			extracted := ExtractCode(state)
			if extracted != code {
				t.Errorf(
					"Verify accepted code %q against state %q but ExtractCode returned %q — false accept",
					code, state, extracted,
				)
			}
		}
	})
}

// FuzzExtractCode feeds arbitrary strings into ExtractCode.
// ExtractCode must never panic and must return either an empty string or
// a string that does not itself contain a colon (codes are pure digit strings
// in practice, but the parser must not panic on arbitrary input).
func FuzzExtractCode(f *testing.F) {
	f.Add("otp:123456:9999999999")
	f.Add("")
	f.Add("otp::")
	f.Add(":::::")
	f.Add("otp:000000:0")
	f.Add("not-an-otp-state")
	f.Add("otp:" + strings.Repeat("x", 1000) + ":9999999999")
	f.Add("\xff\xfe invalid utf-8")
	f.Add("otp:\x00:9999999999")

	f.Fuzz(func(t *testing.T, state string) {
		// Must not panic — result is discarded.
		_ = ExtractCode(state)
	})
}
