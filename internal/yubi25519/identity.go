package yubi25519

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"stevijo.me/yubikey/internal/format"
	"stevijo.me/yubikey/internal/yubikey"
)

var (
	_ age.Identity = new(Identity)
)

const x25519Label = "age-encryption.org/v1/X25519"
const ed25519Label = "age-encryption.org/v1/ssh-ed25519"

type Identity struct {
	x25519Key *piv.X25519PrivateKey
	ssh       ssh.PublicKey
}

// Unwrap implements age.Identity.
func (i *Identity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	for _, stanza := range stanzas {
		r, err := i.unwrap(stanza)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}

		return r, nil
	}

	return nil, age.ErrIncorrectIdentity
}

func (i *Identity) unwrap(block *age.Stanza) ([]byte, error) {
	isSsh := false
	label := x25519Label
	switch block.Type {
	case "ssh-ed25519":
		isSsh = true
		label = ed25519Label
	case "X25519":
	default:
		return nil, age.ErrIncorrectIdentity
	}

	if !isSsh && len(block.Args) != 1 {
		return nil, errors.New("invalid X25519 recipient block")
	}

	if isSsh && len(block.Args) != 2 {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}

	pubArg := block.Args[0]
	if isSsh {
		pubArg = block.Args[1]
		h := sha256.Sum256(i.ssh.Marshal())
		if isSsh && block.Args[0] != format.EncodeToString(h[:4]) {
			return nil, age.ErrIncorrectIdentity
		}
	}

	publicKey, err := format.DecodeString(pubArg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 recipient: %v", err)
	}
	if len(publicKey) != curve25519.PointSize {
		return nil, errors.New("invalid X25519 recipient block")
	}

	ecdhPublicKey, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	yubikeySharedSecret, err := i.x25519Key.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, age.ErrIncorrectIdentity
	}

	if isSsh {
		tweak := make([]byte, curve25519.ScalarSize)
		tH := hkdf.New(sha256.New, nil, i.ssh.Marshal(), []byte(label))
		if _, err := io.ReadFull(tH, tweak); err != nil {
			return nil, err
		}
		yubikeySharedSecret, _ = curve25519.X25519(tweak, yubikeySharedSecret)
	}

	ourPublicKey := i.x25519Key.Public().(*ecdh.PublicKey).Bytes()

	salt := make([]byte, 0, len(publicKey)+len(ourPublicKey))
	salt = append(salt, publicKey...)
	salt = append(salt, ourPublicKey...)
	h := hkdf.New(sha256.New, yubikeySharedSecret, salt, []byte(label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, 16, block.Body)
	if err != nil {
		return nil, age.ErrIncorrectIdentity
	}
	return fileKey, nil
}

// aeadDecrypt decrypts a message of an expected fixed size.
//
// The message size is limited to mitigate multi-key attacks, where a ciphertext
// can be crafted that decrypts successfully under multiple keys. Short
// ciphertexts can only target two keys, which has limited impact.
func aeadDecrypt(key []byte, size int, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != size+aead.Overhead() {
		return nil, errors.New("incorrect aead size")
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}

func ParseIdentity(data []byte, keyPrompter func() (string, error)) (*Identity, error) {
	if len(data) != 6 {
		return nil, errors.New("incorrect identity")
	}
	yk, err := yubikey.FindBySerial(binary.BigEndian.Uint32(data[:4]))
	if err != nil {
		return nil, err
	}

	x25519Slot, ok := piv.RetiredKeyManagementSlot(uint32(data[4]))
	if !ok {
		return nil, errors.New("invalid slot")
	}

	ed25519Slot, ok := piv.RetiredKeyManagementSlot(uint32(data[5]))
	if !ok {
		return nil, errors.New("invalid slot")
	}

	x25519KeyInfo, err := yk.KeyInfo(x25519Slot)
	if err != nil {
		return nil, err
	}

	if x25519KeyInfo.Algorithm != piv.AlgorithmX25519 {
		return nil, errors.New("invalid key type")
	}

	ed25519KeyInfo, err := yk.KeyInfo(ed25519Slot)
	if err != nil {
		return nil, err
	}

	if ed25519KeyInfo.Algorithm != piv.AlgorithmEd25519 {
		return nil, errors.New("invalid key type")
	}

	keyAuth := piv.KeyAuth{
		PINPrompt: keyPrompter,
	}

	private, err := yk.PrivateKey(x25519Slot, x25519KeyInfo.PublicKey, keyAuth)
	if err != nil {
		return nil, err
	}

	ssh, err := ssh.NewPublicKey(ed25519KeyInfo.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Identity{
		x25519Key: private.(*piv.X25519PrivateKey),
		ssh:       ssh,
	}, nil
}
