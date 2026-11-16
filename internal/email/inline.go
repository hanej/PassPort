package email

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// InlineImagePathPrefix is the URL path under which email library images are
// served. Templates reference images with this prefix, and SendHTML swaps
// those references for cid: references to inline MIME parts.
const InlineImagePathPrefix = "/uploads/email-images/"

var (
	inlineMu  sync.RWMutex
	inlineDir string
)

// SetInlineImageDir sets the directory holding email library images. An empty
// dir disables inline embedding.
func SetInlineImageDir(dir string) {
	inlineMu.Lock()
	defer inlineMu.Unlock()
	inlineDir = dir
}

func getInlineImageDir() string {
	inlineMu.RLock()
	defer inlineMu.RUnlock()
	return inlineDir
}

// imgSrcRe matches a quoted src attribute value. Group 1 is the quote, group 2 the value.
var imgSrcRe = regexp.MustCompile(`(?i)\bsrc\s*=\s*(["'])([^"']*)(["'])`)

// inlineFilenameRe restricts embeddable filenames to the server-generated form,
// so a template can never pull in a file outside the image directory.
var inlineFilenameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+\.(?i:png|jpe?g|gif)$`)

// IsInlineImageFilename reports whether name is a valid library image filename.
func IsInlineImageFilename(name string) bool {
	return inlineFilenameRe.MatchString(name)
}

// InlineImageContentType returns the MIME type for an embeddable image
// filename, or "" if the extension is not supported.
func InlineImageContentType(filename string) string {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	}
	return ""
}

type inlineImage struct {
	filename    string
	contentID   string
	contentType string
	data        []byte
}

// inlineFilenameFromSrc returns the library filename referenced by an img src
// (relative or absolute URL), or "" if the src is not a library image.
func inlineFilenameFromSrc(src string) string {
	u, err := url.Parse(strings.TrimSpace(src))
	if err != nil {
		return ""
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if !strings.HasPrefix(u.Path, InlineImagePathPrefix) {
		return ""
	}
	name := strings.TrimPrefix(u.Path, InlineImagePathPrefix)
	if !IsInlineImageFilename(name) {
		return ""
	}
	return name
}

// embedInlineImages rewrites library image references in htmlBody to cid:
// references and loads the referenced files. References whose file cannot be
// read are left untouched so the email still sends.
func embedInlineImages(htmlBody, dir string) (string, []inlineImage) {
	if dir == "" || !strings.Contains(htmlBody, InlineImagePathPrefix) {
		return htmlBody, nil
	}

	var images []inlineImage
	byName := map[string]string{} // filename -> content ID, "" if unreadable

	out := imgSrcRe.ReplaceAllStringFunc(htmlBody, func(m string) string {
		sub := imgSrcRe.FindStringSubmatch(m)
		if sub[1] != sub[3] {
			return m
		}
		name := inlineFilenameFromSrc(sub[2])
		if name == "" {
			return m
		}
		cid, seen := byName[name]
		if !seen {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err == nil {
				cid = name + "@passport"
				images = append(images, inlineImage{
					filename:    name,
					contentID:   cid,
					contentType: InlineImageContentType(name),
					data:        data,
				})
			}
			byName[name] = cid
		}
		if cid == "" {
			return m
		}
		return "src=" + sub[1] + "cid:" + cid + sub[1]
	})
	return out, images
}

// buildMessage assembles the full RFC 5322 message. The HTML is sent
// quoted-printable; when inline images are present the message becomes
// multipart/related with each image as a base64 part referenced by Content-ID.
func buildMessage(fromName, fromAddr, to, subject, htmlBody, priority string, images []inlineImage, now time.Time) ([]byte, error) {
	from := mail.Address{Name: fromName, Address: fromAddr}
	recipient := mail.Address{Address: to}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from.String())
	fmt.Fprintf(&buf, "To: %s\r\n", recipient.String())
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&buf, "Date: %s\r\n", now.Format(time.RFC1123Z))
	// Clients disagree on which header they read, so set all three.
	switch priority {
	case PriorityHigh:
		buf.WriteString("X-Priority: 1 (Highest)\r\nImportance: High\r\nPriority: urgent\r\n")
	case PriorityLow:
		buf.WriteString("X-Priority: 5 (Lowest)\r\nImportance: Low\r\nPriority: non-urgent\r\n")
	}
	buf.WriteString("MIME-Version: 1.0\r\n")

	if len(images) == 0 {
		if err := writeHTMLPart(&buf, htmlBody); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	boundary, err := newBoundary()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&buf, "Content-Type: multipart/related; type=\"text/html\"; boundary=\"%s\"\r\n\r\n", boundary)

	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	if err := writeHTMLPart(&buf, htmlBody); err != nil {
		return nil, err
	}
	buf.WriteString("\r\n")

	for _, img := range images {
		fmt.Fprintf(&buf, "--%s\r\n", boundary)
		fmt.Fprintf(&buf, "Content-Type: %s; name=\"%s\"\r\n", img.contentType, img.filename)
		buf.WriteString("Content-Transfer-Encoding: base64\r\n")
		fmt.Fprintf(&buf, "Content-ID: <%s>\r\n", img.contentID)
		fmt.Fprintf(&buf, "Content-Disposition: inline; filename=\"%s\"\r\n\r\n", img.filename)
		writeBase64Lines(&buf, img.data)
	}
	fmt.Fprintf(&buf, "--%s--\r\n", boundary)
	return buf.Bytes(), nil
}

func writeHTMLPart(buf *bytes.Buffer, htmlBody string) error {
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	qw := quotedprintable.NewWriter(buf)
	if _, err := io.WriteString(qw, htmlBody); err != nil {
		return err
	}
	if err := qw.Close(); err != nil {
		return err
	}
	buf.WriteString("\r\n")
	return nil
}

// writeBase64Lines writes data as base64 wrapped at 76 characters (RFC 2045).
func writeBase64Lines(buf *bytes.Buffer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		buf.WriteString(enc[:76])
		buf.WriteString("\r\n")
		enc = enc[76:]
	}
	if enc != "" {
		buf.WriteString(enc)
		buf.WriteString("\r\n")
	}
}

func newBoundary() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating MIME boundary: %w", err)
	}
	return "passport-" + hex.EncodeToString(b), nil
}
