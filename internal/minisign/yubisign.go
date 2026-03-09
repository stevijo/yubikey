package minisign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"aead.dev/minisign"
	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/blake2b"
	"stevijo.me/yubikey/internal/yubikey"
)

const (
	// Algorithm identifier for hashed format (pre-hashed with Blake2b-512)
	AlgoEdDSAHashed = "ED"
)

// YubiKeySecretKey represents a yubisign secret key (serial + slot reference).
type YubiKeySecretKey struct {
	Serial uint32
	Slot   byte
}

// ParseYubiKeySecretKey parses a yubisign secret key file.
func ParseYubiKeySecretKey(data string) (*YubiKeySecretKey, error) {
	data = strings.TrimSpace(data)
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	if len(decoded) < 5 {
		return nil, fmt.Errorf("key data too short")
	}

	serial := binary.BigEndian.Uint32(decoded[:4])
	slot := decoded[4]
	return &YubiKeySecretKey{Serial: serial, Slot: slot}, nil
}

// ReadYubiKeySecretKeyFile reads and parses a secret key from file.
func ReadYubiKeySecretKeyFile(filename string) (*YubiKeySecretKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseYubiKeySecretKey(string(data))
}

// String returns the base64-encoded secret key.
func (s *YubiKeySecretKey) String() string {
	data := make([]byte, 5)
	binary.BigEndian.PutUint32(data, s.Serial)
	data[4] = s.Slot
	return base64.StdEncoding.EncodeToString(data)
}

// GenerateIdentity generates a new yubisign identity using a YubiKey.
func GenerateIdentity(serialStr string, slotNum int) (*YubiKeySecretKey, *minisign.PublicKey, error) {
	var yk *piv.YubiKey
	var serial uint32
	var err error

	if serialStr != "" {
		var s uint32
		fmt.Sscanf(serialStr, "%d", &s)
		yk, err = yubikey.FindBySerial(s)
		if err != nil {
			return nil, nil, fmt.Errorf("YubiKey not found: %w", err)
		}
		serial = s
	} else {
		yk, err = yubikey.FindFirst()
		if err != nil {
			return nil, nil, err
		}

		serial, err = yk.Serial()
		if err != nil {
			yk.Close()
			return nil, nil, fmt.Errorf("failed to get serial: %w", err)
		}
	}
	defer yk.Close()

	slot, ok := piv.RetiredKeyManagementSlot(uint32(slotNum))
	if !ok {
		return nil, nil, fmt.Errorf("invalid slot %d", slotNum)
	}

	// Get key info
	keyInfo, err := yk.KeyInfo(slot)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get key info: %w", err)
	}

	secretKey := &YubiKeySecretKey{Serial: serial, Slot: byte(slot.Key)}

	// Create public key from keyInfo
	pubKey, err := publicKeyFromKeyInfo(serial, slot.Key, keyInfo)
	if err != nil {
		return nil, nil, err
	}

	return secretKey, pubKey, nil
}

// RestorePublicKey recreates the public key from a secret key using the YubiKey.
func RestorePublicKey(secretKey *YubiKeySecretKey) (*minisign.PublicKey, error) {
	// Find YubiKey
	yk, err := yubikey.FindBySerial(secretKey.Serial)
	if err != nil {
		return nil, fmt.Errorf("YubiKey not found: %w", err)
	}
	defer yk.Close()

	// Get key info
	pivSlot, _ := piv.RetiredKeyManagementSlot(uint32(secretKey.Slot))
	keyInfo, err := yk.KeyInfo(pivSlot)
	if err != nil {
		return nil, fmt.Errorf("could not get key info: %w", err)
	}

	return publicKeyFromKeyInfo(secretKey.Serial, uint32(secretKey.Slot), keyInfo)
}

func publicKeyFromKeyInfo(serial uint32, slot uint32, keyInfo piv.KeyInfo) (*minisign.PublicKey, error) {
	if keyInfo.PublicKey == nil {
		return nil, fmt.Errorf("no public key in slot")
	}
	if keyInfo.Algorithm != piv.AlgorithmEd25519 {
		return nil, fmt.Errorf("slot does not contain Ed25519 key")
	}

	pubBytes := keyInfo.PublicKey.(ed25519.PublicKey)
	keyHash := blake2b.Sum256(pubBytes)
	keyID := keyHash[:8]

	pubKeyData := make([]byte, 2+8+32)
	pubKeyData[0] = 'E'
	pubKeyData[1] = 'd'
	copy(pubKeyData[2:], keyID)
	copy(pubKeyData[10:], pubBytes)

	var pub minisign.PublicKey

	if err := pub.UnmarshalText([]byte(base64.StdEncoding.EncodeToString(
		pubKeyData,
	))); err != nil {
		return nil, err
	}

	return &pub, nil
}

// Signer wraps a YubiKey private key for signing.
type Signer struct {
	YubiKey    *piv.YubiKey
	PIVSlot    piv.Slot
	KeyInfo    piv.KeyInfo
	PrivateKey crypto.PrivateKey
	PublicKey  *minisign.PublicKey
}

// Close closes the YubiKey connection.
func (s *Signer) Close() error {
	return s.YubiKey.Close()
}

// GetSigner obtains a signer from the YubiKey using PIN.
func GetSigner(secretKey *YubiKeySecretKey) (*Signer, error) {
	// Find YubiKey
	yk, err := yubikey.FindBySerial(secretKey.Serial)
	if err != nil {
		return nil, fmt.Errorf("YubiKey not found: %w", err)
	}

	// Get slot and key info
	pivSlot, _ := piv.RetiredKeyManagementSlot(uint32(secretKey.Slot))
	keyInfo, err := yk.KeyInfo(pivSlot)
	if err != nil {
		return nil, fmt.Errorf("slot is empty: %w", err)
	}

	// Get private key
	priv, err := yk.PrivateKey(pivSlot, keyInfo.PublicKey, piv.KeyAuth{
		PINPrompt: func() (string, error) {
			return yubikey.ReadPassword("Enter YubiKey PIN: ")
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Get public key
	pubKey, err := publicKeyFromKeyInfo(secretKey.Serial, uint32(secretKey.Slot), keyInfo)
	if err != nil {
		return nil, err
	}

	return &Signer{
		YubiKey:    yk,
		PIVSlot:    pivSlot,
		KeyInfo:    keyInfo,
		PrivateKey: priv,
		PublicKey:  pubKey,
	}, nil
}

// SignFile signs a file and writes the signature.
func (s *Signer) SignFile(filename, sigFile, trustedComment, untrustedComment string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// Compute hash of file data (Blake2b-512)
	h := blake2b.Sum512(data)

	// Sign the hash using YubiKey
	signer, ok := s.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("key does not support signing")
	}
	rawSig, err := signer.Sign(rand.Reader, h[:], crypto.Hash(0))
	if err != nil {
		return err
	}

	// Default trusted comment if not provided
	if trustedComment == "" {
		trustedComment = fmt.Sprintf("yubisign %d", s.PIVSlot.Key)
	}

	// Compute global signature: ed25519(signature || trusted_comment)
	// Hash it first (matching minisign behavior)
	globalSigData := append(rawSig, []byte(trustedComment)...)
	globalSig, err := signer.Sign(rand.Reader, globalSigData[:], crypto.Hash(0))
	if err != nil {
		return err
	}

	// Create minisign.Signature struct
	sig := minisign.Signature{
		Algorithm:        minisign.HashEdDSA,
		KeyID:            s.PublicKey.ID(),
		TrustedComment:   trustedComment,
		UntrustedComment: untrustedComment,
	}
	copy(sig.Signature[:], rawSig)
	copy(sig.CommentSignature[:], globalSig)

	// Marshal the signature to get the signature line
	sigBytes, err := sig.MarshalText()
	if err != nil {
		return fmt.Errorf("failed to marshal signature: %w", err)
	}

	// Write signature file
	return os.WriteFile(sigFile, sigBytes, 0644)
}
