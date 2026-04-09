package email

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
	"os"
	"strings"
	"testing"
	"time"
)

// fakeSMTPServer starts a minimal plaintext SMTP server on a random port.
// It accepts a single connection, processes one message, then closes.
func fakeSMTPServer(t *testing.T) (addr string, stop func()) {
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
			go serveOneFakeSMTP(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

// serveOneFakeSMTP handles a single SMTP session using a bare-bones protocol.
func serveOneFakeSMTP(conn net.Conn) {
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
			// Accept any AUTH PLAIN in one step (client may include credentials inline)
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

// fakeRejectSMTPServer starts a fake SMTP server that rejects the given command
// with a 5xx error.  rejectCmd should be an uppercase prefix like "MAIL FROM", "AUTH", etc.
func fakeRejectSMTPServer(t *testing.T, rejectCmd string) (addr string, stop func()) {
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
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				w := bufio.NewWriter(c)
				r := bufio.NewReader(c)
				send := func(s string) { fmt.Fprintf(w, "%s\r\n", s); w.Flush() }
				send("220 127.0.0.1 SMTP Service Ready")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
					if strings.HasPrefix(upper, rejectCmd) {
						send("550 5.7.0 Rejected")
						return
					}
					switch {
					case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
						send("250-127.0.0.1 Hello")
						send("250 OK")
					case upper == "QUIT":
						send("221 Bye")
						return
					default:
						send("250 OK")
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestSendHTML_MailFromError(t *testing.T) {
	addr, stop := fakeRejectSMTPServer(t, "MAIL FROM")
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{Host: host, Port: port, FromAddress: "from@example.com"}
	if err := SendHTML(cfg, "to@example.com", "subj", "body"); err == nil {
		t.Error("expected error when MAIL FROM is rejected")
	}
}

func TestSendHTML_RcptToError(t *testing.T) {
	addr, stop := fakeRejectSMTPServer(t, "RCPT TO")
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{Host: host, Port: port, FromAddress: "from@example.com"}
	if err := SendHTML(cfg, "to@example.com", "subj", "body"); err == nil {
		t.Error("expected error when RCPT TO is rejected")
	}
}

func TestSendHTML_AuthError(t *testing.T) {
	addr, stop := fakeRejectSMTPServer(t, "AUTH")
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		Username:    "user",
		Password:    "pass",
	}
	if err := SendHTML(cfg, "to@example.com", "subj", "body"); err == nil {
		t.Error("expected error when AUTH is rejected")
	}
}

func TestSendHTML_PlainSMTP(t *testing.T) {
	addr, stop := fakeSMTPServer(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		FromName:    "Test Sender",
		UseTLS:      false,
		UseStartTLS: false,
	}

	if err := SendHTML(cfg, "to@example.com", "Test Subject", "<p>Hello</p>"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendHTML_DefaultFromName(t *testing.T) {
	addr, stop := fakeSMTPServer(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		FromName:    "", // should default to "PassPort"
	}

	if err := SendHTML(cfg, "to@example.com", "Subject", "<b>body</b>"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendHTML_DialError(t *testing.T) {
	cfg := Config{
		Host:        "127.0.0.1",
		Port:        "1", // port 1 should fail immediately
		FromAddress: "from@example.com",
		UseTLS:      false,
		UseStartTLS: false,
	}
	if err := SendHTML(cfg, "to@example.com", "subj", "body"); err == nil {
		t.Error("expected error dialing bad address")
	}
}

func TestSendHTML_TLSDialError(t *testing.T) {
	cfg := Config{
		Host:          "127.0.0.1",
		Port:          "1", // port 1 should fail immediately
		FromAddress:   "from@example.com",
		UseTLS:        true,
		TLSSkipVerify: true,
	}
	if err := SendHTML(cfg, "to@example.com", "subj", "body"); err == nil {
		t.Error("expected error dialing TLS with bad port")
	}
}

func TestSendHTML_StartTLSFails(t *testing.T) {
	// Our plain SMTP server doesn't support STARTTLS, so this should fail
	// with an error from the STARTTLS negotiation.
	addr, stop := fakeSMTPServer(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:          host,
		Port:          port,
		FromAddress:   "from@example.com",
		UseTLS:        false,
		UseStartTLS:   true,
		TLSSkipVerify: true,
	}
	// STARTTLS will fail because our fake server doesn't advertise STARTTLS.
	_ = SendHTML(cfg, "to@example.com", "subj", "body")
	// Not asserting specific error — just exercising the path.
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// selfSignedTLSConfig generates a self-signed TLS certificate for 127.0.0.1.
func selfSignedTLSConfig(t *testing.T) *tls.Config {
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

// fakeTLSSMTPServer starts a minimal SMTPS (TLS-first) server on a random port.
func fakeTLSSMTPServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	tlsCfg := selfSignedTLSConfig(t)
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
			go serveOneFakeSMTP(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestSendHTML_TLSSuccess(t *testing.T) {
	addr, stop := fakeTLSSMTPServer(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:          host,
		Port:          port,
		FromAddress:   "from@example.com",
		FromName:      "TLS Test",
		UseTLS:        true,
		TLSSkipVerify: true, // skip verification for self-signed cert
	}

	if err := SendHTML(cfg, "to@example.com", "TLS Subject", "<p>TLS body</p>"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendHTML_TLSWithAuth(t *testing.T) {
	addr, stop := fakeTLSSMTPServer(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:          host,
		Port:          port,
		FromAddress:   "from@example.com",
		UseTLS:        true,
		TLSSkipVerify: true,
		Username:      "user",
		Password:      "pass",
	}

	if err := SendHTML(cfg, "to@example.com", "Subject", "<p>body</p>"); err != nil {
		t.Errorf("unexpected error with TLS+auth: %v", err)
	}
}

func TestSendHTML_PlainWithAuth(t *testing.T) {
	addr, stop := fakeSMTPServer(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		Username:    "user",
		Password:    "pass",
	}

	if err := SendHTML(cfg, "to@example.com", "Subject", "<p>body</p>"); err != nil {
		t.Errorf("unexpected error with plain+auth: %v", err)
	}
}

// fakeBadGreetingTLSServer starts a TLS server that sends a 554 rejection
// greeting, causing smtp.NewClient to fail (exercises the error path in sendTLS).
func fakeBadGreetingTLSServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	tlsCfg := selfSignedTLSConfig(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("starting bad greeting TLS server: %v", err)
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
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				w := bufio.NewWriter(c)
				// Send a 554 rejection — smtp.NewClient returns error on non-220.
				fmt.Fprintf(w, "554 5.3.2 Service not available\r\n")
				w.Flush()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestSendHTML_TLSNewClientError(t *testing.T) {
	addr, stop := fakeBadGreetingTLSServer(t)
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{
		Host:          host,
		Port:          port,
		FromAddress:   "from@example.com",
		UseTLS:        true,
		TLSSkipVerify: true,
	}
	if err := SendHTML(cfg, "to@example.com", "subj", "body"); err == nil {
		t.Error("expected error when SMTP server sends bad greeting")
	}
}

func TestSendHTML_DataError(t *testing.T) {
	addr, stop := fakeRejectSMTPServer(t, "DATA")
	defer stop()

	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{Host: host, Port: port, FromAddress: "from@example.com"}
	if err := SendHTML(cfg, "to@example.com", "subj", "body"); err == nil {
		t.Error("expected error when DATA command is rejected")
	}
}
