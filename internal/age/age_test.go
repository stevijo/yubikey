package age

import (
	"filippo.io/age"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptDecryptWithKey tests encryption and decryption using age.GenerateX25519Identity.
func TestEncryptDecryptWithKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "age-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	recipient := identity.Recipient()

	plaintext := []byte("hello world, this is a test of age encryption")

	encryptedFile := filepath.Join(tmpDir, "test.age")
	err = EncryptFile(encryptedFile, plaintext, recipient)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptFile(encryptedFile, identity)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("Decrypted data mismatch")
	}
}

// TestEncryptDecryptWithDifferentKeys tests that encryption with different keys produces different results.
func TestEncryptDecryptWithDifferentKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "age-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identity1, _ := age.GenerateX25519Identity()
	identity2, _ := age.GenerateX25519Identity()

	recipient1 := identity1.Recipient()
	recipient2 := identity2.Recipient()

	plaintext := []byte("test data")

	encrypted1 := filepath.Join(tmpDir, "test1.age")
	EncryptFile(encrypted1, plaintext, recipient1)

	encrypted2 := filepath.Join(tmpDir, "test2.age")
	EncryptFile(encrypted2, plaintext, recipient2)

	data1, _ := os.ReadFile(encrypted1)
	data2, _ := os.ReadFile(encrypted2)

	if string(data1) == string(data2) {
		t.Fatal("Expected different ciphertexts for different keys")
	}

	_, err = DecryptFile(encrypted1, identity2)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong key")
	}

	_, err = DecryptFile(encrypted2, identity1)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong key")
	}
}

// TestDecryptFileNotFound tests decryption with missing file.
func TestDecryptFileNotFound(t *testing.T) {
	_, err := DecryptFile("/nonexistent/file.age")
	if err == nil {
		t.Fatal("Expected error for missing file")
	}
}

// TestEncryptEmptyData tests encryption of empty data.
func TestEncryptEmptyData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "age-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identity, _ := age.GenerateX25519Identity()
	recipient := identity.Recipient()

	plaintext := []byte{}

	encryptedFile := filepath.Join(tmpDir, "test.age")
	err = EncryptFile(encryptedFile, plaintext, recipient)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptFile(encryptedFile, identity)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("Expected empty decrypted data, got %d bytes", len(decrypted))
	}
}

// TestEncryptLargeData tests encryption of larger data.
func TestEncryptLargeData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "age-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identity, _ := age.GenerateX25519Identity()
	recipient := identity.Recipient()

	// Create 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encryptedFile := filepath.Join(tmpDir, "test.age")
	err = EncryptFile(encryptedFile, plaintext, recipient)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptFile(encryptedFile, identity)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Fatalf("Data length mismatch: %d != %d", len(decrypted), len(plaintext))
	}
}
