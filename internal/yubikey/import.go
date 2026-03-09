package yubikey

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

// ErrNoFreeSlots indicates no free slots available.
var ErrNoFreeSlots = errors.New("no free slots available")

// FindFreeRetiredSlots finds free retired key management slots.
// Returns up to n slot numbers that are not currently in use.
func FindFreeRetiredSlots(yk *piv.YubiKey, n int) ([]piv.Slot, error) {
	// Retired key management slots are 0x82-0x95
	var freeSlots []piv.Slot
	for slotNum := uint32(0x82); slotNum <= 0x95; slotNum++ {
		slot, ok := piv.RetiredKeyManagementSlot(slotNum)
		if !ok {
			continue
		}

		// Try to get key info - if it fails, the slot might be free
		_, err := yk.KeyInfo(slot)
		if err != nil {
			// Slot appears to be free or inaccessible
			freeSlots = append(freeSlots, slot)
			if len(freeSlots) >= n {
				break
			}
		}
	}

	if len(freeSlots) < n {
		return nil, fmt.Errorf("%w: found %d, need %d", ErrNoFreeSlots, len(freeSlots), n)
	}

	return freeSlots, nil
}

// FindFirstFreeRetiredSlot finds the first free retired key management slot.
func FindFirstFreeRetiredSlot(yk *piv.YubiKey) (piv.Slot, error) {
	slots, err := FindFreeRetiredSlots(yk, 1)
	if err != nil {
		return piv.Slot{}, err
	}
	return slots[0], nil
}

// ImportX25519Key imports an x25519 private key into a PIV slot.
func ImportX25519Key(yk *piv.YubiKey, pin string, slot piv.Slot, privKey []byte, pinPolicy piv.PINPolicy, touchPolicy piv.TouchPolicy) error {
	if len(privKey) != 32 {
		return errors.New("x25519 private key must be 32 bytes")
	}

	// Create x25519 private key from the bytes
	x25519Priv, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to create x25519 private key: %w", err)
	}

	metadata, err := yk.Metadata(pin)
	if err != nil {
		return err
	}

	// Use default management key (requires PIN to modify)
	managementKey := piv.DefaultManagementKey
	if metadata.ManagementKey != nil {
		managementKey = *metadata.ManagementKey
	}

	// Set the key policy
	policy := piv.Key{
		Algorithm:   piv.AlgorithmX25519,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	}

	// Import the key
	err = yk.SetPrivateKeyInsecure(managementKey, slot, x25519Priv, policy)
	if err != nil {
		return fmt.Errorf("failed to import x25519 key: %w", err)
	}

	return nil
}

// ImportEd25519Key imports an ed25519 private key into a PIV slot.
// Note: Requires YubiKey 5.7+ with PIV 2.0+ support.
func ImportEd25519Key(yk *piv.YubiKey, pin string, slot piv.Slot, privKey []byte, pinPolicy piv.PINPolicy, touchPolicy piv.TouchPolicy) error {
	// Ed25519 private key handling
	var edPriv ed25519.PrivateKey

	if len(privKey) == 32 {
		// Seed only - create the full key
		edPriv = ed25519.NewKeyFromSeed(privKey)
	} else if len(privKey) == 64 {
		// Full key - convert to ed25519.PrivateKey
		edPriv = ed25519.PrivateKey(privKey)
	} else {
		return errors.New("ed25519 private key must be 32 or 64 bytes")
	}

	metadata, err := yk.Metadata(pin)
	if err != nil {
		return err
	}

	// Use default management key (requires PIN to modify)
	managementKey := piv.DefaultManagementKey
	if metadata.ManagementKey != nil {
		managementKey = *metadata.ManagementKey
	}

	// Set the key policy
	policy := piv.Key{
		Algorithm:   piv.AlgorithmEd25519,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	}

	// Import the key
	err = yk.SetPrivateKeyInsecure(managementKey, slot, edPriv, policy)
	if err != nil {
		return fmt.Errorf("failed to import ed25519 key: %w", err)
	}

	return nil
}

// GetSlotKeyInfo retrieves the public key info from a slot.
func GetSlotKeyInfo(yk *piv.YubiKey, slot piv.Slot) (piv.KeyInfo, error) {
	return yk.KeyInfo(slot)
}
