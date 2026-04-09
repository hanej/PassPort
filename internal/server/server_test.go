package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNew(t *testing.T) {
	mux := http.NewServeMux()
	srv := New(":9090", mux, testLogger())

	if srv.httpServer.Addr != ":9090" {
		t.Fatalf("expected addr :9090, got %s", srv.httpServer.Addr)
	}
	if srv.httpServer.ReadTimeout != 30*time.Second {
		t.Fatalf("expected ReadTimeout 30s, got %v", srv.httpServer.ReadTimeout)
	}
	if srv.httpServer.WriteTimeout != 30*time.Second {
		t.Fatalf("expected WriteTimeout 30s, got %v", srv.httpServer.WriteTimeout)
	}
	if srv.httpServer.IdleTimeout != 120*time.Second {
		t.Fatalf("expected IdleTimeout 120s, got %v", srv.httpServer.IdleTimeout)
	}
}

func TestStartAndShutdown(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := New("127.0.0.1:0", mux, testLogger())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("start returned unexpected error: %v", err)
	}
}

func TestGracefulShutdownOnSignal(t *testing.T) {
	mux := http.NewServeMux()
	srv := New("127.0.0.1:0", mux, testLogger())

	go func() {
		_ = srv.Start()
	}()

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		srv.GracefulShutdown(5 * time.Second)
		close(done)
	}()

	// Allow the signal handler to register.
	time.Sleep(50 * time.Millisecond)

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("finding process: %v", err)
	}
	if err := proc.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("sending SIGINT: %v", err)
	}

	select {
	case <-done:
		// Success: GracefulShutdown returned after the signal.
	case <-time.After(5 * time.Second):
		t.Fatal("GracefulShutdown did not return within timeout")
	}
}

func TestStartTLS_InvalidCert(t *testing.T) {
	mux := http.NewServeMux()
	srv := New("127.0.0.1:0", mux, testLogger())

	err := srv.StartTLS("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent cert/key files")
	}
}

func TestStartTLS_Success(t *testing.T) {
	// Generate a self-signed RSA key and certificate for the test.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encoding cert: %v", err)
	}
	_ = cf.Close()
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	_ = kf.Close()
	mux := http.NewServeMux()
	srv := New("127.0.0.1:0", mux, testLogger())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.StartTLS(certFile, keyFile)
	}()

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("StartTLS returned unexpected error: %v", err)
	}
}

// TestStart_AddressInUse verifies that Start returns an error when the
// configured address is already in use.
func TestStart_AddressInUse(t *testing.T) {
	// Bind a listener to claim a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Try to start a server on the same address.
	srv := New(ln.Addr().String(), http.NewServeMux(), testLogger())
	err = srv.Start()
	if err == nil {
		t.Error("expected Start to return an error when address is in use")
	}
}
