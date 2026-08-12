package idp

import "testing"

func TestProviderType_IsDirectory(t *testing.T) {
	tests := []struct {
		typ  ProviderType
		want bool
	}{
		{ProviderTypeAD, true},
		{ProviderTypeFreeIPA, true},
		{ProviderTypeWebLink, false},
		{ProviderType(""), false},
		{ProviderType("unknown"), false},
		{ProviderType("AD"), false},
	}

	for _, tt := range tests {
		if got := tt.typ.IsDirectory(); got != tt.want {
			t.Errorf("ProviderType(%q).IsDirectory() = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

// TestNormalizeWebLinkURL_RejectsUnsafe covers the stored-XSS guard: a weblink
// URL is rendered into an href on the unauthenticated login page, so anything
// that is not an absolute http(s) URL must be rejected outright.
func TestNormalizeWebLinkURL_RejectsUnsafe(t *testing.T) {
	unsafe := []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)",
		"JAVASCRIPT:alert(document.cookie)",
		"  javascript:alert(1)  ",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"ftp://files.example.com",
		"mailto:admin@example.com",
		"ldap://ldap.example.com",
		"//evil.example.com",
		"/admin/idp",
		"../../etc/passwd",
		"example.com",
		"http:example.com",
		"http://",
		"https://",
		"",
		"   ",
		"\t\n",
		"://example.com",
	}

	for _, raw := range unsafe {
		if got := NormalizeWebLinkURL(raw); got != "" {
			t.Errorf("NormalizeWebLinkURL(%q) = %q, want \"\"", raw, got)
		}
	}
}

func TestNormalizeWebLinkURL_AcceptsHTTPAndHTTPS(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://portal.example.com", "https://portal.example.com"},
		{"http://portal.example.com", "http://portal.example.com"},
		{"https://portal.example.com/sso?next=/home#top", "https://portal.example.com/sso?next=/home#top"},
		{"https://portal.example.com:8443/sso", "https://portal.example.com:8443/sso"},
		{"http://10.0.0.1/", "http://10.0.0.1/"},
		{"  https://portal.example.com  ", "https://portal.example.com"},
		{"HTTPS://portal.example.com", "https://portal.example.com"},
	}

	for _, tt := range tests {
		if got := NormalizeWebLinkURL(tt.raw); got != tt.want {
			t.Errorf("NormalizeWebLinkURL(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

// TestIsReservedID guards the slugs that identify built-in pseudo-providers.
// A real provider using one would be rendered and reordered as the built-in
// card instead of itself.
func TestIsReservedID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"local", true},
		{"LOCAL", true},
		{" local ", true},
		{"local-ad", false},
		{"locals", false},
		{"corp-ad", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsReservedID(tt.id); got != tt.want {
			t.Errorf("IsReservedID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestValidID(t *testing.T) {
	valid := []string{"corp-ad", "ad1", "a", "0"}
	for _, id := range valid {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, want true", id)
		}
	}

	// Slugs become a primary key and part of the uploaded logo filename, so
	// path separators, traversal, and a trailing newline must all be rejected.
	invalid := []string{"", "Corp-AD", "corp ad", "corp_ad", "../etc", "a/b", "corp-ad\n", "café"}
	for _, id := range invalid {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, want false", id)
		}
	}
}
