package email

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEmbedInlineImages_RewritesLibraryReferences(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "abc123.png"), []byte("PNGDATA"), 0o644); err != nil {
		t.Fatal(err)
	}

	html := `<img src="/uploads/email-images/abc123.png" alt="a">` +
		`<img src='https://pp.example.com/uploads/email-images/abc123.png'>` +
		`<img src="/uploads/email-images/missing.png">` +
		`<img src="/uploads/email-images/../../etc/passwd.png">` +
		`<img src="https://cdn.example.com/x.png">`

	out, images := embedInlineImages(html, dir)

	if len(images) != 1 {
		t.Fatalf("expected one deduplicated image, got %d", len(images))
	}
	if images[0].contentID != "abc123.png@passport" || images[0].contentType != "image/png" || string(images[0].data) != "PNGDATA" {
		t.Errorf("unexpected image: %+v", images[0])
	}
	if strings.Count(out, `cid:abc123.png@passport`) != 2 {
		t.Errorf("expected both references rewritten, got %s", out)
	}
	for _, keep := range []string{
		`src="/uploads/email-images/missing.png"`,
		`src="/uploads/email-images/../../etc/passwd.png"`,
		`src="https://cdn.example.com/x.png"`,
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("expected %s to be left unchanged, got %s", keep, out)
		}
	}
}

func TestEmbedInlineImages_DisabledWithoutDir(t *testing.T) {
	html := `<img src="/uploads/email-images/abc.png">`
	out, images := embedInlineImages(html, "")
	if out != html || images != nil {
		t.Errorf("expected no change without a dir, got %q %v", out, images)
	}
}

func TestBuildMessage_MultipartRelated(t *testing.T) {
	img := inlineImage{filename: "abc.png", contentID: "abc.png@passport", contentType: "image/png", data: bytes.Repeat([]byte{0x89, 'P'}, 100)}
	raw, err := buildMessage("Sender", "from@example.com", "to@example.com", "Hi", `<img src="cid:abc.png@passport">`, PriorityNormal, []inlineImage{img}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/related" {
		t.Fatalf("expected multipart/related, got %q (%v)", mediaType, err)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	htmlPart, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(htmlPart.Header.Get("Content-Type"), "text/html") {
		t.Errorf("first part should be HTML, got %s", htmlPart.Header.Get("Content-Type"))
	}
	// multipart.Reader decodes quoted-printable parts transparently.
	body, _ := io.ReadAll(htmlPart)
	if !strings.Contains(string(body), `cid:abc.png@passport`) {
		t.Errorf("HTML part missing cid reference: %s", body)
	}

	imgPart, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if imgPart.Header.Get("Content-ID") != "<abc.png@passport>" {
		t.Errorf("unexpected Content-ID %q", imgPart.Header.Get("Content-ID"))
	}
	if !strings.HasPrefix(imgPart.Header.Get("Content-Disposition"), "inline") {
		t.Errorf("expected inline disposition, got %q", imgPart.Header.Get("Content-Disposition"))
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Errorf("expected exactly two parts, got err=%v", err)
	}
}

func TestBuildMessage_SinglePartWithoutImages(t *testing.T) {
	raw, err := buildMessage("Sender", "from@example.com", "to@example.com", "Hi", `<p style="x">Hello</p>`, PriorityNormal, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if ct := msg.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
	body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if !strings.Contains(string(body), `<p style="x">Hello</p>`) {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestSendHTML_EmbedsLibraryImages(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "logo.gif"), []byte("GIF89a"), 0o644); err != nil {
		t.Fatal(err)
	}
	SetInlineImageDir(dir)
	t.Cleanup(func() { SetInlineImageDir("") })

	var captured strings.Builder
	addr, stop := fakeSMTPServer(t, &captured)
	defer stop()
	host, port, _ := net.SplitHostPort(addr)

	cfg := Config{Host: host, Port: port, FromAddress: "from@example.com"}
	if err := SendHTML(cfg, "to@example.com", "Subj", `<img src="/uploads/email-images/logo.gif">`); err != nil {
		t.Fatalf("send: %v", err)
	}
	stop()

	got := captured.String()
	if !strings.Contains(got, "multipart/related") || !strings.Contains(got, "Content-ID: <logo.gif@passport>") {
		t.Errorf("expected inline image in sent message, got:\n%s", got)
	}
}

func TestInlineImageContentType(t *testing.T) {
	for name, want := range map[string]string{"a.png": "image/png", "a.JPG": "image/jpeg", "a.jpeg": "image/jpeg", "a.gif": "image/gif", "a.svg": ""} {
		if got := InlineImageContentType(name); got != want {
			t.Errorf("InlineImageContentType(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestInlineFilenameFromSrc_RejectsOtherSchemes(t *testing.T) {
	for _, src := range []string{"data:/uploads/email-images/a.png", "%zz", "/uploads/email-images/a.svg"} {
		if got := inlineFilenameFromSrc(src); got != "" {
			t.Errorf("inlineFilenameFromSrc(%q) = %q, want empty", src, got)
		}
	}
}

func TestBuildMessage_PriorityHeaders(t *testing.T) {
	cases := map[string][3]string{
		PriorityHigh:   {"1 (Highest)", "High", "urgent"},
		PriorityLow:    {"5 (Lowest)", "Low", "non-urgent"},
		PriorityNormal: {"", "", ""},
	}
	for priority, want := range cases {
		raw, err := buildMessage("S", "from@example.com", "to@example.com", "Hi", "<p>x</p>", priority, nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		msg, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		got := [3]string{msg.Header.Get("X-Priority"), msg.Header.Get("Importance"), msg.Header.Get("Priority")}
		if got != want {
			t.Errorf("%s: got headers %v, want %v", priority, got, want)
		}
	}
}

func TestNormalizePriority(t *testing.T) {
	for in, want := range map[string]string{"high": PriorityHigh, "low": PriorityLow, "": PriorityNormal, "urgent": PriorityNormal} {
		if got := NormalizePriority(in); got != want {
			t.Errorf("NormalizePriority(%q) = %q, want %q", in, got, want)
		}
	}
}
