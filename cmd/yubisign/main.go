package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"stevijo.me/yubikey/internal/minisign"
	"stevijo.me/yubikey/internal/yubikey"
)

const version = "v0.1.0"

const usage = `Usage:
    yubisign -G [-p <pubKey>] [-s <secKey>] [--serial <serial>] [-k <slot>]
    yubisign -R [-s <secKey>] [-p <pubKey>]
    yubisign -S [-x <signature>] [-s <secKey>] [-c <comment>] [-t <comment>] -m <file>...

Options:
    -G               Generate a new yubisign identity (requires YubiKey)
    -R               Re-create a public key file from secret key (using YubiKey)
    -S               Sign files with a YubiKey secret key
    -m <file>        The file to sign
    -o               Combined with -V, output the file after verification
    -p <pubKey>      Public key file (default: ./yubisign.pub)
    -s <secKey>      Secret key file (default: $HOME/.yubisign/yubisign.key)
    -W               Do not encrypt/decrypt the secret key with a password
    -x <signature>   Signature file (default: <file>.minisig)
    -c <comment>     Add a one-line untrusted comment
    -t <comment>     Add a one-line trusted comment
    -q               Quiet mode. Suppress output
    -Q               Pretty quiet mode. Combined with -V, only print the trusted comment
    -f               Combined with -G or -R, overwrite any existing public/secret key pair
    --serial <serial> YubiKey serial number (for -G)
    -k <slot>        PIV slot number (for -G)
    -v               Print version information
`

var (
	flagKeyGen  bool
	flagRestore bool
	flagSign    bool

	flagPrivateKeyFile string
	flagPublicKeyFile  string
	flagFiles          = filenames{}
	flagSignatureFile  string

	flagTrustedComment   string
	flagUntrustedComment string

	flagOutput          bool
	flagPreHash         bool
	flagWithoutPassword bool
	flagPrettyQuiet     bool
	flagQuiet           bool
	flagForce           bool
	flagVersion         bool

	flagYubiKeySerial string
	flagYubiKeySlot   int
)

type filenames []string

func (f *filenames) Set(s string) error {
	*f = append(*f, s)
	return nil
}

func (f filenames) String() string {
	return strings.Join(f, ", ")
}

func main() {
	defer yubikey.CloseAll()
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	flag.BoolVar(&flagKeyGen, "G", false, "")
	flag.BoolVar(&flagRestore, "R", false, "")
	flag.BoolVar(&flagSign, "S", false, "")

	// Set default key locations
	homeDir, _ := os.UserHomeDir()
	defaultKeyFile := filepath.Join(homeDir, ".yubisign", "yubisign.key")
	defaultPubFile := filepath.Join(homeDir, ".yubisign", "yubisign.pub")

	flag.StringVar(&flagPrivateKeyFile, "s", defaultKeyFile, "")
	flag.StringVar(&flagPublicKeyFile, "p", defaultPubFile, "")
	flag.Var(&flagFiles, "m", "")
	flag.StringVar(&flagSignatureFile, "x", "", "")

	flag.StringVar(&flagTrustedComment, "t", "", "")
	flag.StringVar(&flagUntrustedComment, "c", "", "")

	flag.BoolVar(&flagOutput, "o", false, "")
	flag.BoolVar(&flagPreHash, "H", false, "")
	flag.BoolVar(&flagWithoutPassword, "W", false, "")
	flag.BoolVar(&flagPrettyQuiet, "Q", false, "")
	flag.BoolVar(&flagQuiet, "q", false, "")
	flag.BoolVar(&flagForce, "f", false, "")
	flag.BoolVar(&flagVersion, "v", false, "")

	flag.StringVar(&flagYubiKeySerial, "serial", "", "")
	flag.IntVar(&flagYubiKeySlot, "k", 0, "")

	flag.Parse()

	if flagVersion {
		fmt.Printf("yubisign %s\n", version)
		os.Exit(0)
	}

	count := 0
	if flagKeyGen {
		count++
	}
	if flagRestore {
		count++
	}
	if flagSign {
		count++
	}
	if count == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if count > 1 {
		fmt.Fprintln(os.Stderr, "Error: Only one of -G, -R, -S, -V can be specified")
		os.Exit(1)
	}

	if flagKeyGen {
		handleKeyGen()
	} else if flagRestore {
		handleRestore()
	} else if flagSign {
		handleSign()
	}
}

func handleKeyGen() {
	secretKey, publicKey, err := minisign.GenerateIdentity(flagYubiKeySerial, flagYubiKeySlot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(flagPrivateKeyFile), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create directory: %v\n", err)
		os.Exit(1)
	}

	// Write secret key
	if err := os.WriteFile(flagPrivateKeyFile, []byte(secretKey.String()), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to write secret key: %v\n", err)
		os.Exit(1)
	}

	// Write public key
	data, err := publicKey.MarshalText()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to marshal public key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(flagPublicKeyFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to write public key: %v\n", err)
		os.Exit(1)
	}

	if !flagQuiet {
		fmt.Printf("Generated identity for YubiKey serial: %d, slot: %d\n", secretKey.Serial, secretKey.Slot)
		fmt.Printf("Public key file: %s\n", flagPublicKeyFile)
		fmt.Printf("Secret key file: %s\n", flagPrivateKeyFile)
	}
}

func handleRestore() {
	// Read secret key
	secretKey, err := minisign.ReadYubiKeySecretKeyFile(flagPrivateKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Could not read secret key: %v\n", err)
		os.Exit(1)
	}

	// Restore public key from YubiKey
	publicKey, err := minisign.RestorePublicKey(secretKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to restore public key: %v\n", err)
		os.Exit(1)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(flagPublicKeyFile), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create directory: %v\n", err)
		os.Exit(1)
	}

	// Write public key
	if err := os.WriteFile(flagPublicKeyFile, []byte(publicKey.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to write public key: %v\n", err)
		os.Exit(1)
	}

	if !flagQuiet {
		fmt.Printf("Restored public key for YubiKey serial: %d, slot: %d\n", secretKey.Serial, secretKey.Slot)
		fmt.Printf("Public key file: %s\n", flagPublicKeyFile)
	}
}

func handleSign() {
	if len(flagFiles) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No files specified")
		os.Exit(1)
	}

	// Read secret key
	secretKey, err := minisign.ReadYubiKeySecretKeyFile(flagPrivateKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Could not read secret key: %v\n", err)
		os.Exit(1)
	}

	// Get signer
	signer, err := minisign.GetSigner(secretKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to get signer: %v\n", err)
		os.Exit(1)
	}

	// Sign each file
	for _, filename := range flagFiles {
		sigFile := flagSignatureFile
		if sigFile == "" {
			sigFile = filename + ".minisig"
		}

		err = signer.SignFile(filename, sigFile, flagTrustedComment, flagUntrustedComment)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to sign %s: %v\n", filename, err)
			os.Exit(1)
		}

		if !flagQuiet {
			fmt.Printf("Signed: %s -> %s\n", filename, sigFile)
		}
	}
}
