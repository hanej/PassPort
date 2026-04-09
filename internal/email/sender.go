// Package email provides reusable SMTP email sending functionality.
package email

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
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

// SendHTML sends an HTML email with the given subject, body, and recipient.
func SendHTML(cfg Config, to, subject, htmlBody string) error {
	addr := net.JoinHostPort(cfg.Host, cfg.Port)

	fromName := cfg.FromName
	if fromName == "" {
		fromName = "PassPort"
	}

	msg := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Date: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n",
		fromName, cfg.FromAddress, to, subject,
		time.Now().Format(time.RFC1123Z), htmlBody,
	)

	// Set up authentication if credentials are provided.
	var auth smtp.Auth
	if cfg.Username != "" && cfg.Password != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.UseTLS {
		// Direct TLS connection (port 465 typically).
		return sendTLS(addr, cfg.Host, cfg.TLSSkipVerify, auth, cfg.FromAddress, to, []byte(msg))
	}

	// Plain SMTP or STARTTLS -- connect plaintext first.
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial: %w", err)
	}
	defer client.Close()

	// Upgrade with STARTTLS if configured.
	if cfg.UseStartTLS {
		tlsConfig := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec // user-controlled option
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	return smtpSend(client, auth, cfg.FromAddress, to, []byte(msg))
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
		conn.Close()
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer client.Close()

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
