package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"stevijo.me/yubikey/internal/crypto"
	"stevijo.me/yubikey/internal/yubikey"
)

var (
	serialFlag  = flag.String("serial", "", "Target YubiKey serial number")
	slotFlag    = flag.Int("slot", 0, "First slot to use (default: auto-find)")
	dryRunFlag  = flag.Bool("dry-run", false, "Show what would be done without importing")
	pinFlag     = flag.String("pin", "", "YubiKey PIN (will prompt if not provided)")
)

func main() {
	flag.Parse()

	// Read mnemonic from stdin (never from CLI to avoid bash history)
	reader := bufio.NewReader(os.Stdin)
	mnemonic, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: Failed to read mnemonic from stdin")
		os.Exit(1)
	}
	mnemonic = strings.TrimSpace(mnemonic)
	if mnemonic == "" {
		fmt.Fprintln(os.Stderr, "Error: No mnemonic provided via stdin")
		os.Exit(1)
	}

	// Derive 32-byte key from mnemonic
	seed, err := crypto.DeriveKeyFromMnemonic(mnemonic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to derive key: %v\n", err)
		os.Exit(1)
	}

	// Derive x25519 key from ed25519 seed
	x25519Key, err := crypto.Ed25519ToX25519(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to derive x25519 key: %v\n", err)
		os.Exit(1)
	}

	// Find YubiKey
	var yk *piv.YubiKey

	if *serialFlag != "" {
		var serial uint32
		fmt.Sscanf(*serialFlag, "%d", &serial)
		yk, err = yubikey.FindBySerial(serial)
	} else {
		yk, err = yubikey.FindFirst()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to find YubiKey: %v\n", err)
		os.Exit(1)
	}
	defer yk.Close()

	serial, _ := yk.Serial()
	fmt.Printf("Using YubiKey serial: %d\n", serial)

	// Find free slots
	slots, err := yubikey.FindFreeRetiredSlots(yk, 2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: No free slots: %v\n", err)
		os.Exit(1)
	}

	startSlot := *slotFlag
	if startSlot == 0 {
		startSlot = int(slots[0].Key)
	}

	x25519Slot, _ := piv.RetiredKeyManagementSlot(uint32(startSlot + 1))
	ed25519Slot, _ := piv.RetiredKeyManagementSlot(uint32(startSlot))

	fmt.Printf("x25519 slot: 0x%02x\n", x25519Slot.Key)
	fmt.Printf("ed25519 slot: 0x%02x\n", ed25519Slot.Key)

	if *dryRunFlag {
		fmt.Println("\nDry run - keys not imported")
		return
	}

	// Get PIN
	pin := *pinFlag
	if pin == "" {
		pin, err = yubikey.ReadPassword("Enter YubiKey PIN: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to read PIN: %v\n", err)
			os.Exit(1)
		}
		pin = strings.TrimSpace(pin)
	}

	if err := yk.VerifyPIN(pin); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid PIN: %v\n", err)
		os.Exit(1)
	}

	// Import x25519 key
	err = yubikey.ImportX25519Key(yk, pin, x25519Slot, x25519Key, piv.PINPolicyOnce, piv.TouchPolicyCached)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to import x25519 key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Imported x25519 key")

	// Import ed25519 key
	err = yubikey.ImportEd25519Key(yk, pin, ed25519Slot, seed, piv.PINPolicyOnce, piv.TouchPolicyNever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to import ed25519 key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Imported ed25519 key")

	fmt.Println("\nSuccess!")
}
