package yubikey

import (
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"sync"
	"unsafe"

	"cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/devices/yubikey"
	"cunicu.li/go-iso7816/drivers/pcsc"
	"github.com/ebfe/scard"
	"github.com/go-piv/piv-go/v2/piv"
)

// ShareMode defines the smart card share mode.
type ShareMode = scard.ShareMode

const (
	ShareShared    ShareMode = scard.ShareShared
	ShareExclusive ShareMode = scard.ShareExclusive
)

// yubikeys holds cached YubiKey instances, keyed by serial number.
var yubikeys = make(map[uint32]*piv.YubiKey)
var mu sync.Mutex

// cache stores a YubiKey in the cache.
func cache(yk *piv.YubiKey) error {
	serial, err := yk.Serial()
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	yubikeys[serial] = yk
	return nil
}

// CloseAll closes all cached YubiKey connections.
func CloseAll() {
	mu.Lock()
	defer mu.Unlock()
	for serial, yk := range yubikeys {
		yk.Close()
		delete(yubikeys, serial)
	}
}

type handleHolder struct {
	handle uintptr
}

type version struct {
	major byte
	minor byte
	patch byte
}

func setFieldValue[T any](yk *piv.YubiKey, fieldName string, t T) {
	r := reflect.ValueOf(yk).Elem()

	field := r.FieldByName(fieldName)
	if field == (reflect.Value{}) {
		return
	}

	fieldType := field.Type()

	// Set the field in YubiKey using the field index
	reflect.NewAt(
		fieldType,
		unsafe.Pointer(field.UnsafeAddr()),
	).Elem().Set(
		reflect.NewAt(
			fieldType,
			unsafe.Pointer(&t),
		).Elem(),
	)
}

// Open opens a YubiKey with the specified share mode.
// This allows multiple processes to access the YubiKey concurrently when using ShareShared.
// Currently, piv.Open is used internally, which opens in SHARE_SHARED mode by default.
func Open(reader string, mode ShareMode) (*piv.YubiKey, error) {
	// Try to connect using scard first to verify the share mode works
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, err
	}

	// Try to connect with the specified mode
	card, err := pcsc.NewCard(ctx, reader, true)
	if err != nil {
		return nil, err
	}

	yubikey := yubikey.NewCard(card)
	err = yubikey.BeginTransaction()
	if err != nil {
		return nil, err
	}

	pivId := [...]byte{0xa0, 0x00, 0x00, 0x03, 0x08}
	_, err = yubikey.Send(&iso7816.CAPDU{
		Ins:  0xa4,
		P1:   0x04,
		Data: pivId[:],
	})
	if err != nil {
		return nil, err
	}

	versionBytes, err := yubikey.Send(&iso7816.CAPDU{
		Ins: 0xfd,
	})
	if err != nil {
		return nil, err
	}

	// Get the handle from scard.Card using reflection
	cardValue := reflect.ValueOf(card.Base().(*pcsc.Card).Card)
	cardHandle := reflect.Indirect(cardValue).FieldByName("handle").Uint()

	// Get the context from scard.Context using reflection
	ctxValue := reflect.ValueOf(ctx)
	ctxHandle := reflect.Indirect(ctxValue).FieldByName("ctx").Uint()

	// Create YubiKey and fill fields via reflection
	yk := &piv.YubiKey{}

	// Fill ctx, h, and tx fields
	setFieldValue(yk, "ctx", &handleHolder{
		uintptr(ctxHandle),
	})
	setFieldValue(yk, "h", &handleHolder{
		uintptr(cardHandle),
	})
	setFieldValue(yk, "tx", &handleHolder{
		uintptr(cardHandle),
	})

	setFieldValue(yk, "rand", rand.Reader)

	setFieldValue(yk, "version", &version{
		major: versionBytes[0],
		minor: versionBytes[1],
		patch: versionBytes[2],
	})

	// Cache the YubiKey
	_ = cache(yk)

	return yk, nil
}

func FindBySerial(serial uint32) (*piv.YubiKey, error) {
	// Check cache first
	mu.Lock()
	if yk, ok := yubikeys[serial]; ok {
		mu.Unlock()
		return yk, nil
	}
	mu.Unlock()

	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	var yk *piv.YubiKey
	cardErrors := make([]error, 0)
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yubi, err := Open(card, ShareShared)
			if err != nil {
				cardErrors = append(cardErrors, err)
				continue
			}

			ySerial, err := yubi.Serial()
			if err != nil {
				cardErrors = append(cardErrors, err)
				continue
			}

			if ySerial == serial {
				yk = yubi
				break
			}
		}
	}

	if yk == nil {
		if len(cardErrors) != 0 {
			return nil, errors.Join(cardErrors...)
		}

		return nil, errors.New("no yubikey found")
	}

	// Cache the YubiKey
	_ = cache(yk)

	return yk, nil
}

// FindFirst finds the first available YubiKey.
func FindFirst() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	var yk *piv.YubiKey

	yubikeyCards := make([]string, 0)
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yubikeyCards = append(yubikeyCards, card)
		}
	}

	if len(yubikeyCards) == 1 {
		// Check cache first - if there's exactly one, return it
		mu.Lock()
		if len(yubikeys) == 1 {
			for _, yk := range yubikeys {
				mu.Unlock()
				return yk, nil
			}
		}
		mu.Unlock()

		yk, err = Open(yubikeyCards[0], ShareShared)
	}

	if yk == nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("no yubikey found")
	}

	return yk, nil
}
