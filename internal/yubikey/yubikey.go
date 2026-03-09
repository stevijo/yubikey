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
	ykValue := reflect.ValueOf(yk).Elem()
	ykType := ykValue.Type()

	// Helper to set a pointer field with a struct containing a handle
	setHandleField := func(fieldName string, handle uint64) {
		field, ok := ykType.FieldByName(fieldName)
		if !ok {
			return
		}
		// Create new struct for the handle
		elemType := field.Type.Elem() // e.g., scContext from *scContext
		elemVal := reflect.New(elemType)

		handleField := elemVal.Elem().Field(0)
		// Set first field (the handle)
		reflect.NewAt(
			handleField.Type(),
			unsafe.Pointer(handleField.UnsafeAddr()),
		).Elem().SetInt(int64(handle))
		// Set the field in YubiKey using the field index
		reflect.NewAt(
			ykValue.Field(field.Index[0]).Type(),
			unsafe.Pointer(ykValue.Field(field.Index[0]).UnsafeAddr()),
		).Elem().Set(elemVal)
	}

	// Fill ctx, h, and tx fields
	setHandleField("ctx", ctxHandle)
	setHandleField("h", cardHandle)
	setHandleField("tx", cardHandle)

	// Set rand field
	if randField, ok := ykType.FieldByName("rand"); ok {
		reflect.NewAt(
			ykValue.Field(randField.Index[0]).Type(),
			unsafe.Pointer(ykValue.Field(randField.Index[0]).UnsafeAddr()),
		).Elem().Set(reflect.ValueOf(rand.Reader))
	}

	// Set version field (YubiKey 5.7.3)
	if versionField, ok := ykType.FieldByName("version"); ok {
		versionType := versionField.Type.Elem()
		versionVal := reflect.New(versionType)

		// Set Major field
		majorField := versionVal.Elem().Field(0)
		reflect.NewAt(
			majorField.Type(),
			unsafe.Pointer(majorField.UnsafeAddr()),
		).Elem().SetUint(uint64(versionBytes[0]))

		// Set Minor field
		minorField := versionVal.Elem().Field(1)
		reflect.NewAt(
			minorField.Type(),
			unsafe.Pointer(minorField.UnsafeAddr()),
		).Elem().SetUint(uint64(versionBytes[1]))

		// Set Patch field
		patchField := versionVal.Elem().Field(2)
		reflect.NewAt(
			patchField.Type(),
			unsafe.Pointer(patchField.UnsafeAddr()),
		).Elem().SetUint(uint64(versionBytes[2]))

		reflect.NewAt(
			ykValue.Field(versionField.Index[0]).Type(),
			unsafe.Pointer(ykValue.Field(versionField.Index[0]).UnsafeAddr()),
		).Elem().Set(versionVal)
	}

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
