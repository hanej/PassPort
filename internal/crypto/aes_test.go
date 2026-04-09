package crypto

import (
	"bytes"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)
	svc, err := NewService(key, 1)
	if err != nil {
		t.Fatalf("creating service: %v", err)
	}

	plaintext := []byte("sensitive password data")
	blob, err := svc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	got, err := svc.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("expected %q, got %q", plaintext, got)
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key := testKey(t)
	svc, err := NewService(key, 1)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := svc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("encrypting empty: %v", err)
	}

	got, err := svc.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypting empty: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("expected empty, got %d bytes", len(got))
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := testKey(t)
	svc, err := NewService(key, 1)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("same input")
	blob1, _ := svc.Encrypt(plaintext)
	blob2, _ := svc.Encrypt(plaintext)

	if bytes.Equal(blob1, blob2) {
		t.Error("two encryptions of the same plaintext should produce different ciphertexts")
	}

	// Both should decrypt to the same value
	p1, _ := svc.Decrypt(blob1)
	p2, _ := svc.Decrypt(blob2)
	if !bytes.Equal(p1, p2) {
		t.Error("both ciphertexts should decrypt to same plaintext")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)
	svc1, _ := NewService(key1, 1)
	svc2, _ := NewService(key2, 1)

	blob, _ := svc1.Encrypt([]byte("secret"))
	_, err := svc2.Decrypt(blob)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecryptUnknownVersion(t *testing.T) {
	key := testKey(t)
	svc, _ := NewService(key, 1)

	blob, _ := svc.Encrypt([]byte("secret"))

	svc2, _ := NewService(key, 2) // only knows version 2
	_, err := svc2.Decrypt(blob)  // blob has version 1
	if err == nil {
		t.Error("expected error for unknown key version")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := testKey(t)
	svc, _ := NewService(key, 1)

	_, err := svc.Decrypt(make([]byte, overhead-1))
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

func TestDecryptCorrupted(t *testing.T) {
	key := testKey(t)
	svc, _ := NewService(key, 1)

	blob, _ := svc.Encrypt([]byte("secret"))
	// Flip a byte in the ciphertext
	blob[len(blob)-1] ^= 0xff

	_, err := svc.Decrypt(blob)
	if err == nil {
		t.Error("expected error for corrupted ciphertext")
	}
}

func TestKeyRotation(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	// Encrypt with version 1
	svc1, _ := NewService(key1, 1)
	blob1, _ := svc1.Encrypt([]byte("data-v1"))

	// Create service with version 2 as current, add version 1 for decryption
	svc2, _ := NewService(key2, 2)
	if err := svc2.AddKey(key1, 1); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	// Should decrypt old blob using version 1 key
	got, err := svc2.Decrypt(blob1)
	if err != nil {
		t.Fatalf("decrypting v1 blob with v2 service: %v", err)
	}
	if string(got) != "data-v1" {
		t.Errorf("expected data-v1, got %s", got)
	}

	// New encryptions use version 2
	blob2, _ := svc2.Encrypt([]byte("data-v2"))
	got2, _ := svc2.Decrypt(blob2)
	if string(got2) != "data-v2" {
		t.Errorf("expected data-v2, got %s", got2)
	}
}

func TestNewServiceInvalidKeySize(t *testing.T) {
	_, err := NewService(make([]byte, 16), 1)
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}

func TestAddKeyInvalidSize(t *testing.T) {
	key := testKey(t)
	svc, _ := NewService(key, 1)
	err := svc.AddKey(make([]byte, 16), 2)
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}

func TestCurrentVersion(t *testing.T) {
	key := testKey(t)
	svc, _ := NewService(key, 42)
	if svc.CurrentVersion() != 42 {
		t.Errorf("expected version 42, got %d", svc.CurrentVersion())
	}
}

func TestEncrypt_VersionNotInKeys(t *testing.T) {
	key := testKey(t)
	svc, _ := NewService(key, 1)

	// Remove the current version key to force the "version not found" error.
	delete(svc.keys, 1)

	_, err := svc.Encrypt([]byte("test"))
	if err == nil {
		t.Error("expected error when current key version is not in keys map")
	}
}

func TestGenerateKey(t *testing.T) {
	k1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != KeySize {
		t.Errorf("expected %d bytes, got %d", KeySize, len(k1))
	}

	k2, _ := GenerateKey()
	if bytes.Equal(k1, k2) {
		t.Error("two generated keys should not be equal")
	}
}

func TestWireFormat(t *testing.T) {
	key := testKey(t)
	svc, _ := NewService(key, 1)

	blob, _ := svc.Encrypt([]byte("test"))

	// Verify minimum size
	if len(blob) < overhead {
		t.Errorf("blob too small: %d bytes", len(blob))
	}

	// Verify version bytes
	if blob[0] != 0 || blob[1] != 0 || blob[2] != 0 || blob[3] != 1 {
		t.Errorf("expected version 1 in big-endian, got %x", blob[:4])
	}
}
