package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tyler-smith/go-bip39"
)

var (
	wordCountFlag = flag.Int("words", 24, "Number of words (12, 15, 18, 21, or 24)")
)

func main() {
	flag.Parse()

	// Validate word count
	entropies := map[int]int{
		12: 128,
		15: 160,
		18: 192,
		21: 224,
		24: 256,
	}
	bits, ok := entropies[*wordCountFlag]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: Invalid word count: %d (must be 12, 15, 18, 21, or 24)\n", *wordCountFlag)
		os.Exit(1)
	}

	// Generate entropy
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to generate entropy: %v\n", err)
		os.Exit(1)
	}

	// Generate mnemonic
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to generate mnemonic: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(mnemonic)
}
