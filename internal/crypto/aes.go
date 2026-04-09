package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// keyVersionSize is the size of the key version prefix in the wire format.
	keyVersionSize = 4

	// nonceSize is the size of the AES-GCM nonce.
	nonceSize = 12

	// overhead is the minimum size of an encrypted blob (version + nonce + GCM tag).
	overhead = keyVersionSize + nonceSize + 16 // 16 = GCM tag size
)

// Service handles encryption and decryption of secrets using AES-256-GCM.
// It supports key versioning for rotation: the current key version is used for
// encryption, and all known key versions can be used for decryption.
type Service struct {
	currentVersion uint32
	keys           map[uint32][]byte
}

// NewService creates a new crypto service with the given key and version.
func NewService(key []byte, version uint32) (*Service, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}
	return &Service{
		currentVersion: version,
		keys:           map[uint32][]byte{version: key},
	}, nil
}

// AddKey registers an additional key version for decryption (key rotation support).
func (s *Service) AddKey(key []byte, version uint32) error {
	if len(key) != KeySize {
		return fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}
	s.keys[version] = key
	return nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the current key version.
// Wire format: [keyVersion:4 big-endian | nonce:12 | ciphertext+GCM-tag]
func (s *Service) Encrypt(plaintext []byte) ([]byte, error) {
	key, ok := s.keys[s.currentVersion]
	if !ok {
		return nil, fmt.Errorf("current key version %d not found", s.currentVersion)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Build wire format: [version:4 | nonce:12 | ciphertext+tag]
	blob := make([]byte, keyVersionSize+len(nonce)+len(ciphertext))
	binary.BigEndian.PutUint32(blob[:keyVersionSize], s.currentVersion)
	copy(blob[keyVersionSize:keyVersionSize+nonceSize], nonce)
	copy(blob[keyVersionSize+nonceSize:], ciphertext)

	return blob, nil
}

// Decrypt decrypts a blob encrypted by Encrypt, using the key version embedded in the blob.
func (s *Service) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < overhead {
		return nil, fmt.Errorf("ciphertext too short: %d bytes, minimum %d", len(blob), overhead)
	}

	version := binary.BigEndian.Uint32(blob[:keyVersionSize])
	key, ok := s.keys[version]
	if !ok {
		return nil, fmt.Errorf("unknown key version %d", version)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := blob[keyVersionSize : keyVersionSize+nonceSize]
	ciphertext := blob[keyVersionSize+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// CurrentVersion returns the key version used for encryption.
func (s *Service) CurrentVersion() uint32 {
	return s.currentVersion
}

// GenerateKey generates a cryptographically random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}
