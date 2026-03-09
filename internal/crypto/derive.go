package crypto

import (
	"crypto/sha512"
	"errors"

	"github.com/tyler-smith/go-bip39"
)

// DeriveKeyFromMnemonic derives a 32-byte key from a BIP39 mnemonic.
// It generates the seed from the mnemonic (using an empty passphrase)
func DeriveKeyFromMnemonic(mnemonic string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic")
	}

	seed, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	return seed, nil
}

// Ed25519ToX25519 converts an ed25519 private key to an x25519 private key.
// This follows RFC 7748: the scalar is "clamped" before use.
// The ed25519 private key should be 32 bytes (the seed), not the expanded form.
func Ed25519ToX25519(ed25519Priv []byte) ([]byte, error) {
	if len(ed25519Priv) != 32 {
		return nil, errors.New("ed25519 private key must be 32 bytes")
	}

	x25519Key := sha512.Sum512(ed25519Priv)

	return x25519Key[:32], nil
}

// GenerateMnemonic generates a new BIP39 mnemonic with 256 bits of entropy.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}
