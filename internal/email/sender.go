// Package email provides reusable SMTP email sending functionality.
package email

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Config holds SMTP configuration (combines config + decrypted secrets).
type Config struct {
	Host          string
	Port          string
	FromAddress   string
	FromName      string
	UseTLS        bool
	UseStartTLS   bool
	TLSSkipVerify bool
	Username      string
	Password      string
}

// validateHeaderValue rejects a value that is about to be interpolated into
// a raw email header if it contains an embedded CR or LF character. Without
// this check, a subject line, recipient address, or display name pulled
// from a directory attribute or an admin-editable template could inject
// additional headers such as "Bcc:", override "Content-Type:", or split
// the message into attacker-controlled parts (CWE-93 email header
// injection). Rejecting outright (rather than silently stripping) ensures
// malformed/malicious input is surfaced as an error instead of being sent.
func validateHeaderValue(name, s string) error {
	if strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("invalid %s: contains CR or LF", name)
	}
	return nil
}

// Priority values for an email. PriorityNormal adds no priority headers.
const (
	PriorityNormal = "normal"
	PriorityHigh   = "high"
	PriorityLow    = "low"
)

// NormalizePriority maps any unrecognised value (including "") to PriorityNormal.
func NormalizePriority(p string) string {
	switch p {
	case PriorityHigh, PriorityLow:
		return p
	}
	return PriorityNormal
}

// SendHTML sends an HTML email with the given subject, body, and recipient at
// normal priority.
func SendHTML(cfg Config, to, subject, htmlBody string) error {
	return SendHTMLWithPriority(cfg, to, subject, htmlBody, PriorityNormal)
}

// SendHTMLWithPriority sends an HTML email, marking it high or low priority
// when requested.
func SendHTMLWithPriority(cfg Config, to, subject, htmlBody, priority string) error {
	addr := net.JoinHostPort(cfg.Host, cfg.Port)

	fromName := cfg.FromName
	if fromName == "" {
		fromName = "PassPort"
	}

	if err := validateHeaderValue("from name", fromName); err != nil {
		return err
	}
	if err := validateHeaderValue("from address", cfg.FromAddress); err != nil {
		return err
	}
	if err := validateHeaderValue("to", to); err != nil {
		return err
	}
	if err := validateHeaderValue("subject", subject); err != nil {
		return err
	}
	fromAddress := cfg.FromAddress

	body, images := embedInlineImages(htmlBody, getInlineImageDir())
	msg, err := buildMessage(fromName, fromAddress, to, subject, body, NormalizePriority(priority), images, time.Now())
	if err != nil {
		return fmt.Errorf("building message: %w", err)
	}

	// Set up authentication if credentials are provided.
	var auth smtp.Auth
	if cfg.Username != "" && cfg.Password != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.UseTLS {
		// Direct TLS connection (port 465 typically).
		return sendTLS(addr, cfg.Host, cfg.TLSSkipVerify, auth, fromAddress, to, []byte(msg))
	}

	// Plain SMTP or STARTTLS -- connect plaintext first.
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Upgrade with STARTTLS if configured.
	if cfg.UseStartTLS {
		tlsConfig := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec // user-controlled option
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	return smtpSend(client, auth, fromAddress, to, []byte(msg))
}

// sendTLS sends via a direct TLS connection (SMTPS, typically port 465).
func sendTLS(addr, host string, skipVerify bool, auth smtp.Auth, from, to string, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify} //nolint:gosec // user-controlled option
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial: %w", err)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	return smtpSend(client, auth, from, to, msg)
}

// smtpSend performs the AUTH, MAIL FROM, RCPT TO, DATA sequence on an smtp.Client.
func smtpSend(client *smtp.Client, auth smtp.Auth, from, to string, msg []byte) error {
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("AUTH: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("closing message: %w", err)
	}
	return client.Quit()
}
