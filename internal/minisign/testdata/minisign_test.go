package minisign

import (
	"os"
	"path/filepath"
	"testing"
)

// TestVerifyWithStaticSignature tests verification with a known valid signature.
func TestVerifyWithStaticSignature(t *testing.T) {
	// Use static test data
	pubKeyData, err := os.ReadFile("testdata/public.pubkey")
	if err != nil {
		t.Fatal(err)
	}

	sigData, err := os.ReadFile("testdata/valid.minisig")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("testdata/valid.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Parse public key
	pubKey, err := ParsePublicKey(string(pubKeyData))
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Parse signature
	var sig Signature
	if err := sig.UnmarshalText(sigData); err != nil {
		t.Fatalf("Failed to parse signature: %v", err)
	}

	// Verify
	if !Verify(pubKey.key, data, sigData) {
		t.Fatal("Verification failed")
	}
}

// TestVerifyWithStaticSignatureWrongData tests verification with tampered data.
func TestVerifyWithStaticSignatureWrongData(t *testing.T) {
	pubKeyData, _ := os.ReadFile("testdata/public.pubkey")
	sigData, _ := os.ReadFile("testdata/valid.minisig")

	// Tampered data
	data := []byte("wrong content")

	pubKey, _ := ParsePublicKey(string(pubKeyData))

	// Verification should fail
	if Verify(pubKey.key, data, sigData) {
		t.Fatal("Expected verification to fail with wrong data")
	}
}
