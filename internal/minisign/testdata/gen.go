package main

import (
	"fmt"
	"os"
	"aead.dev/minisign"
)

func main() {
	// Generate a key pair
	pk, sk, _ := minisign.GenerateKey(nil)

	// Sign test file content
	data := []byte("hello world")
	sigBytes := minisign.Sign(sk, data)

	// Unmarshal to get the struct
	var sig minisign.Signature
	sig.UnmarshalText(sigBytes)

	// Get public key
	pubKeyBytes, _ := pk.MarshalText()

	// Write test files
	os.WriteFile("test.pubkey", pubKeyBytes, 0644)
	os.WriteFile("test.txt.minisig", sigBytes, 0644)
	os.WriteFile("test.txt", data, 0644)

	fmt.Printf("Public key:\n%s\n", string(pubKeyBytes))
	fmt.Printf("\nSignature:\n%s\n", string(sigBytes))
}
