package age

import (
	"bytes"
	"fmt"
	"filippo.io/age"
	"io"
	"os"

	"stevijo.me/yubikey/internal/bech32"
	"stevijo.me/yubikey/internal/crypto"
)

// DecryptFile decrypts an age-encrypted file using the provided identities.
func DecryptFile(filename string, identities ...age.Identity) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := age.Decrypt(f, identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// DecryptWithMnemonic decrypts an age-encrypted file using a BIP39 mnemonic.
// It derives an x25519 key from the mnemonic and uses it as the age identity.
func DecryptWithMnemonic(filename, mnemonic string) ([]byte, error) {
	key, err := crypto.DeriveKeyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	return DecryptWithKey(filename, key)
}

// DecryptWithKey decrypts an age-encrypted file using a raw x25519 key.
func DecryptWithKey(filename string, key []byte) ([]byte, error) {
	// Convert key to age identity format
	ageKey, err := bech32.Encode("AGE-SECRET-KEY-", key)
	if err != nil {
		return nil, err
	}

	identity, err := age.ParseX25519Identity(ageKey)
	if err != nil {
		return nil, err
	}

	return DecryptFile(filename, identity)
}

// Encrypt encrypts data using age with the given recipients.
func Encrypt(data []byte, recipients ...age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients provided")
	}

	buf := new(bytes.Buffer)
	writer, err := age.Encrypt(buf, recipients...)
	if err != nil {
		return nil, err
	}

	_, err = writer.Write(data)
	if err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncryptWithKey encrypts data using a raw x25519 key.
func EncryptWithKey(filename string, data []byte, key []byte) error {
	// Convert key to age recipient format
	ageKey, err := bech32.Encode("AGE-SECRET-KEY-", key)
	if err != nil {
		return err
	}

	recipient, err := age.ParseX25519Recipient(ageKey)
	if err != nil {
		return err
	}

	return EncryptFile(filename, data, recipient)
}

// EncryptFile encrypts data to an age-encrypted file using a recipient.
func EncryptFile(filename string, data []byte, recipients ...age.Recipient) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	if len(recipients) == 0 {
		return fmt.Errorf("no recipients provided")
	}

	writer, err := age.Encrypt(f, recipients...)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	if err != nil {
		return err
	}

	return writer.Close()
}
