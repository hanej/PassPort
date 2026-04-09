package handler

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

// fakeSMTPServerHandler starts a minimal plaintext SMTP server for handler tests.
func fakeSMTPServerHandler(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting fake SMTP server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHandlerFakeSMTP(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func serveHandlerFakeSMTP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	send := func(s string) {
		fmt.Fprintf(w, "%s\r\n", s)
		w.Flush()
	}

	send("220 127.0.0.1 SMTP Service Ready")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			send("250-127.0.0.1 Hello")
			send("250 OK")
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			send("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM"):
			send("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			send("250 OK")
		case upper == "DATA":
			send("354 Start mail input; end with <CRLF>.<CRLF>")
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
			}
			send("250 OK: Message queued")
		case upper == "QUIT":
			send("221 Bye")
			return
		default:
			send("500 Command unrecognized")
		}
	}
}

// selfSignedTLSConfigHandler generates a self-signed TLS certificate for 127.0.0.1.
func selfSignedTLSConfigHandler(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("loading key pair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// fakeTLSSMTPServerHandler starts a minimal SMTPS (TLS-first) server for handler tests.
func fakeTLSSMTPServerHandler(t *testing.T) (addr string, stop func()) {
	t.Helper()
	tlsCfg := selfSignedTLSConfigHandler(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("starting fake TLS SMTP server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHandlerFakeSMTP(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestSendEmail_PlainSMTPSuccess(t *testing.T) {
	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := SMTPConfigFields{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		FromName:    "Test Sender",
		UseTLS:      false,
		UseStartTLS: false,
	}

	if err := sendEmail(cfg, SMTPSecrets{}, "to@example.com", "Test Subject", "<p>Hello</p>"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendEmail_PlainSMTPWithAuth(t *testing.T) {
	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := SMTPConfigFields{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
	}
	secrets := SMTPSecrets{Username: "user", Password: "pass"}

	if err := sendEmail(cfg, secrets, "to@example.com", "Test Subject", "<p>Hello</p>"); err != nil {
		t.Errorf("unexpected error with auth: %v", err)
	}
}

func TestSendEmail_TLSSMTPSuccess(t *testing.T) {
	addr, stop := fakeTLSSMTPServerHandler(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := SMTPConfigFields{
		Host:          host,
		Port:          port,
		FromAddress:   "from@example.com",
		UseTLS:        true,
		TLSSkipVerify: true,
	}

	if err := sendEmail(cfg, SMTPSecrets{}, "to@example.com", "TLS Subject", "<p>TLS Hello</p>"); err != nil {
		t.Errorf("unexpected error with TLS: %v", err)
	}
}

func TestSendEmail_TLSSMTPWithAuth(t *testing.T) {
	addr, stop := fakeTLSSMTPServerHandler(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := SMTPConfigFields{
		Host:          host,
		Port:          port,
		FromAddress:   "from@example.com",
		UseTLS:        true,
		TLSSkipVerify: true,
	}
	secrets := SMTPSecrets{Username: "user", Password: "pass"}

	if err := sendEmail(cfg, secrets, "to@example.com", "TLS Subject", "<p>TLS Hello</p>"); err != nil {
		t.Errorf("unexpected error with TLS+auth: %v", err)
	}
}

func TestSmtpSend_PlainSMTP(t *testing.T) {
	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dialing fake SMTP: %v", err)
	}
	defer client.Close()

	if err := smtpSend(client, nil, "from@example.com", "to@example.com", []byte("Subject: Test\r\n\r\nBody")); err != nil {
		t.Errorf("unexpected error from smtpSend: %v", err)
	}
}

// serveSmtpRejectCmd serves a single SMTP connection and rejects the first command
// whose uppercase representation starts with rejectPrefix.
func serveSmtpRejectCmd(conn net.Conn, rejectPrefix string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	send := func(s string) {
		fmt.Fprintf(w, "%s\r\n", s)
		w.Flush()
	}

	send("220 127.0.0.1 SMTP Service Ready")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		// Reject and close if this command matches the reject prefix.
		if rejectPrefix != "" && strings.HasPrefix(upper, rejectPrefix) {
			send("500 Error: command rejected")
			return
		}

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			send("250-127.0.0.1 Hello")
			send("250 OK")
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			send("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM"):
			send("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			send("250 OK")
		case upper == "DATA":
			send("354 Start mail input; end with <CRLF>.<CRLF>")
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
			}
			send("250 OK: Message queued")
		case upper == "QUIT":
			send("221 Bye")
			return
		default:
			send("500 Command unrecognized")
		}
	}
}

// fakeSmtpServerRejectCmd starts a fake SMTP server that rejects any command
// whose uppercase prefix starts with rejectPrefix.
func fakeSmtpServerRejectCmd(t *testing.T, rejectPrefix string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting fake reject SMTP server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSmtpRejectCmd(conn, rejectPrefix)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

// fakeTLSSMTPBadGreetingServer starts a TLS SMTP server that sends a 421 response
// instead of a 220 greeting, causing smtp.NewClient to fail.
func fakeTLSSMTPBadGreetingServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	tlsCfg := selfSignedTLSConfigHandler(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("starting fake TLS bad-greeting server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Send 421 instead of 220 — smtp.NewClient expects 220.
				fmt.Fprintf(c, "421 Service not available\r\n")
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

// TestSmtpSend_AuthError verifies that smtpSend returns an AUTH error when the
// server rejects the AUTH command.
func TestSmtpSend_AuthError(t *testing.T) {
	addr, stop := fakeSmtpServerRejectCmd(t, "AUTH")
	defer stop()

	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dialing fake SMTP: %v", err)
	}
	defer client.Close()

	// PlainAuth is permitted on localhost (127.0.0.1) without TLS.
	auth := smtp.PlainAuth("", "user", "pass", "127.0.0.1")
	err = smtpSend(client, auth, "from@example.com", "to@example.com", []byte("Subject: Test\r\n\r\nBody"))
	if err == nil {
		t.Error("expected AUTH error, got nil")
	}
}

// TestSmtpSend_MailFromError verifies that smtpSend returns a MAIL FROM error
// when the server rejects the MAIL FROM command.
func TestSmtpSend_MailFromError(t *testing.T) {
	addr, stop := fakeSmtpServerRejectCmd(t, "MAIL")
	defer stop()

	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dialing fake SMTP: %v", err)
	}
	defer client.Close()

	err = smtpSend(client, nil, "from@example.com", "to@example.com", []byte("Subject: Test\r\n\r\nBody"))
	if err == nil {
		t.Error("expected MAIL FROM error, got nil")
	}
}

// TestSmtpSend_RcptToError verifies that smtpSend returns a RCPT TO error
// when the server rejects the RCPT TO command.
func TestSmtpSend_RcptToError(t *testing.T) {
	addr, stop := fakeSmtpServerRejectCmd(t, "RCPT")
	defer stop()

	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dialing fake SMTP: %v", err)
	}
	defer client.Close()

	err = smtpSend(client, nil, "from@example.com", "to@example.com", []byte("Subject: Test\r\n\r\nBody"))
	if err == nil {
		t.Error("expected RCPT TO error, got nil")
	}
}

// TestSmtpSend_DataError verifies that smtpSend returns a DATA error when the
// server rejects the DATA command.
func TestSmtpSend_DataError(t *testing.T) {
	addr, stop := fakeSmtpServerRejectCmd(t, "DATA")
	defer stop()

	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dialing fake SMTP: %v", err)
	}
	defer client.Close()

	err = smtpSend(client, nil, "from@example.com", "to@example.com", []byte("Subject: Test\r\n\r\nBody"))
	if err == nil {
		t.Error("expected DATA error, got nil")
	}
}

// TestSendEmailTLS_NewClientError verifies that sendEmailTLS returns an error when
// smtp.NewClient fails because the server sends 421 instead of the expected 220 greeting.
func TestSendEmailTLS_NewClientError(t *testing.T) {
	addr, stop := fakeTLSSMTPBadGreetingServer(t)
	defer stop()

	host, _, _ := net.SplitHostPort(addr)
	err := sendEmailTLS(addr, host, true, nil, "from@example.com", "to@example.com", []byte("msg"))
	if err == nil {
		t.Error("expected error when smtp.NewClient receives 421 instead of 220")
	}
}

// TestSendEmail_StartTLSFailure verifies that sendEmail returns an error when
// UseStartTLS is true but the server does not support STARTTLS.
func TestSendEmail_StartTLSFailure(t *testing.T) {
	addr, stop := fakeSMTPServerHandler(t) // plain server — no STARTTLS support
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := SMTPConfigFields{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		UseStartTLS: true,
		UseTLS:      false,
	}
	err := sendEmail(cfg, SMTPSecrets{}, "to@example.com", "Test Subject", "<p>body</p>")
	if err == nil {
		t.Error("expected StartTLS error against plain server that does not support STARTTLS")
	}
}
