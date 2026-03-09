package main

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"strconv"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/go-piv/piv-go/v2/piv"
	"stevijo.me/yubikey/internal/bech32"
	"stevijo.me/yubikey/internal/yubi25519"
	"stevijo.me/yubikey/internal/yubikey"
)

const usage = `age-plugin-yubi25519: age plugin for YubiKey 5.7.0+ with support for ed25519 keys.`

// Version can be set at link time to override debug.BuildInfo.Main.Version when
// building manually without git history. It should look like "v1.2.3".
var Version string

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	p, err := plugin.New("yubi25519")
	if err != nil {
		errorf("failed to create plugin: %v", err)
	}
	p.RegisterFlags(nil)

	var outFlag, slot, ed25519Slot, serial string
	var versionFlag, identityFlag bool
	flag.BoolVar(&versionFlag, "version", false, "print the version")
	flag.BoolVar(&identityFlag, "identity", false, "convert identities to plugin identities")
	flag.StringVar(&slot, "slot", "", "yubikey retired slot")
	flag.StringVar(&ed25519Slot, "ed25519Slot", "", "yubikey retired slot for ed25519")
	flag.StringVar(&slot, "serial", "", "yubikey serial number")
	flag.StringVar(&outFlag, "o", "", "output to `FILE` (default stdout)")
	flag.StringVar(&outFlag, "output", "", "output to `FILE` (default stdout)")

	flag.Parse()

	if versionFlag {
		if buildInfo, ok := debug.ReadBuildInfo(); ok && Version == "" {
			Version = buildInfo.Main.Version
		}
		fmt.Println(Version)
		return
	}

	if identityFlag {
		if len(flag.Args()) > 0 {
			errorf("too many arguments")
		}

		if slot == "" {
			errorf("no yubikey slot specified")
		}
		if ed25519Slot == "" {
			errorf("no ed25519 yubikey slot specified")
		}

		out := os.Stdout
		if outFlag != "" {
			f, err := os.OpenFile(outFlag, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				errorf("failed to open output file %q: %v", outFlag, err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					errorf("failed to close output file %q: %v", outFlag, err)
				}
			}()
			out = f
		}
		if fi, err := out.Stat(); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
			warning("writing secret key to a world-readable file")
		}

		convert(serial, slot, ed25519Slot, out)
		return
	}

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return yubi25519.ParseIdentity(data, func() (string, error) {
			return p.RequestValue("Enter the PIN for YubiKey", true)
		})
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		if len(data) != 5 {
			return nil, errors.New("incorrect payload")
		}
		serial := binary.BigEndian.Uint32(data[:4])

		yk, err := yubikey.FindBySerial(serial)
		if err != nil {
			return nil, err
		}

		yk.Close()

		retiredSlot, ok := piv.RetiredKeyManagementSlot(uint32(data[4]))
		if !ok {
			return nil, errors.New("incorrect slot")
		}

		keyInfo, err := yk.KeyInfo(retiredSlot)
		if err != nil {
			return nil, fmt.Errorf("could not get keyinfo from slot %s %v", slot, err)
		}

		if keyInfo.Algorithm != piv.AlgorithmX25519 {
			return nil, errors.New("key must be x25519 key")
		}

		x25519key, err := bech32.Encode("age", keyInfo.PublicKey.(*ecdh.PublicKey).Bytes())
		if err != nil {
			return nil, err
		}

		return age.ParseX25519Recipient(x25519key)
	})

	ret := p.Main()

	yubikey.CloseAll()
	os.Exit(ret)
}

func convert(serial, slot, ed25519Slot string, out io.Writer) {
	r, err := strconv.ParseUint(slot, 16, 32)
	if err != nil {
		errorf("incorrect slot %v", err)
	}

	ed, err := strconv.ParseUint(ed25519Slot, 16, 32)
	if err != nil {
		errorf("incorrect slot %v", err)
	}


	s, err := strconv.ParseUint(slot, 10, 32)
	if err != nil {
		errorf("incorrect serial %v", err)
	}


	var yk *piv.YubiKey
	if serial == "" {
		yk, err = yubikey.FindFirst()
	} else {
		yk, err = yubikey.FindBySerial(uint32(s))
	}

	if err != nil {
		errorf("can't open yubikey %v", err)
	}
	defer yk.Close()

	retiredSlot, ok := piv.RetiredKeyManagementSlot(uint32(r))
	if !ok {
		errorf("incorrect slot")
	}

	keyInfo, err := yk.KeyInfo(retiredSlot)
	if err != nil {
		errorf("could not get keyinfo from slot %s %v", slot, err)
	}

	if keyInfo.Algorithm != piv.AlgorithmX25519 {
		errorf("key must be x25519 key")
	}

	yubikeySerial, err := yk.Serial()
	if err != nil {
		errorf("couldn't retrieve serial number %v", err)
	}

	data := make([]byte, 6)
	binary.BigEndian.PutUint32(data, yubikeySerial)
	data[4] = byte(r)
	data[5] = byte(ed)
	recipient, _ := bech32.Encode("age", keyInfo.PublicKey.(*ecdh.PublicKey).Bytes())
	fmt.Fprintf(out, "# public key: %s\n", recipient)
	fmt.Fprintln(out, plugin.EncodeIdentity("yubi25519", data))
}

func errorf(format string, v ...any) {
	log.Printf("age-plugin-yubi25519: error: "+format, v...)
	log.Fatalf("age-plugin-yubi25519: report unexpected or unhelpful errors at https://filippo.io/age/report")
}

func warning(msg string) {
	log.Printf("age-plugin-yubi25519: warning: %s", msg)
}
