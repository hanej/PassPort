package crypto

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadMasterKeyFromEnv(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	t.Setenv(EnvMasterKey, encoded)

	got, err := LoadMasterKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(got))
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatalf("byte %d: expected %d, got %d", i, i, b)
		}
	}
}

func TestLoadMasterKeyFromEnvURLSafeBase64(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	t.Setenv(EnvMasterKey, encoded)

	got, err := LoadMasterKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(got))
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatalf("byte %d: expected %d, got %d", i, i, b)
		}
	}
}

func TestLoadMasterKeyFromEnvURLSafeBase64WithPadding(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i + 200)
	}
	encoded := base64.URLEncoding.EncodeToString(key)
	t.Setenv(EnvMasterKey, encoded)

	got, err := LoadMasterKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(got))
	}
}

func TestLoadMasterKeyFromEnvWrongSize(t *testing.T) {
	t.Setenv(EnvMasterKey, base64.StdEncoding.EncodeToString(make([]byte, 16)))
	_, err := LoadMasterKey()
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestLoadMasterKeyFromEnvInvalidBase64(t *testing.T) {
	t.Setenv(EnvMasterKey, "not-valid-base64!!!")
	_, err := LoadMasterKey()
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestLoadFromFileRawBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i + 100)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := loadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(got))
	}
	for i, b := range got {
		if b != byte(i+100) {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestLoadFromFileBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i + 50)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := loadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, b := range got {
		if b != byte(i+50) {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestLoadFromFileWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, make([]byte, 10), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := loadFromFile(path)
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestLoadFromFileMissing(t *testing.T) {
	_, err := loadFromFile("/nonexistent/path/key")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadMasterKeyNotFound(t *testing.T) {
	t.Setenv(EnvMasterKey, "")
	_, err := LoadMasterKey()
	if err == nil {
		t.Fatal("expected error when no key source available")
	}
}

func TestKeyFilePath_NotWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test only valid on non-Windows platforms")
	}
	path := keyFilePath()
	if path != "/etc/passport/key" {
		t.Errorf("expected /etc/passport/key, got %s", path)
	}
}
