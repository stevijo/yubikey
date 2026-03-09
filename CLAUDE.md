# YubiKey Management Tools

Simple tools for managing YubiKeys with ed25519 and x25519 keys in the PIV applet.

### 0. Mnemonic Generator (`cmd/mnemonic/`)
Generates a BIP39 mnemonic for bootstrapping YubiKey secrets.

- **Location**: `cmd/mnemonic/main.go`
- **Usage**: `./mnemonic` or `./mnemonic -words 24` (default: 24)

## Project Overview

### 1. Age Plugin (`extra/age-plugin-yubi25519/`)
An age plugin that uses x25519 keys stored in the YubiKey PIV applet.

- **Location**: `extra/age-plugin-yubi25519/plugin-yubi25519.go`
- **Identity format**: Serial number (4 bytes) + slot number (1 byte)

### 2. YubiSign Tool (`cmd/yubisign/`)
A minisign-compatible CLI tool that uses ed25519 keys stored in the YubiKey PIV applet for signing.

- **Location**: `cmd/yubisign/main.go`
- **Key storage**: Ed25519 keys in PIV retired slots (0x82-0x95)
- **CLI flags**:
  - `-G` - Generate identity (requires YubiKey)
  - `-R` - Recreate public key from secret key
  - `-S` - Sign files
  - `-V` - Verify signatures

### 3. Duplication Tool (`cmd/duplicate/`)
Imports ed25519 and x25519 keys from a BIP39 mnemonic to a YubiKey.

- **Location**: `cmd/duplicate/main.go`
- **Usage**: Mnemonic is read from stdin only (never CLI to avoid bash history)
- **Options**:
  - `-serial` - Target YubiKey serial
  - `-slot` - First slot to use (default: auto)
  - `-dry-run` - Show what would be done
  - `-pin` - YubiKey PIN (will prompt if not set)

## Internal Packages

### `internal/yubikey/`
- YubiKey discovery and PIV key management
- `FindBySerial()` - Find YubiKey by serial
- `ImportX25519Key()` / `ImportEd25519Key()` - Import keys to PIV
- `FindFreeRetiredSlots()` - Find available slots

### `internal/crypto/`
- Key derivation from BIP39 mnemonic
- Ed25519 to x25519 conversion

### `internal/minisign/`
- Minisign wrapper for YubiKey signing

### `internal/age/`
- Age encryption with YubiKey x25519 keys

## Dependencies

```go
filippo.io/age          // Age encryption
github.com/go-piv/piv-go // YubiKey PIV communication
github.com/tyler-smith/go-bip39 // BIP39 mnemonic handling
golang.org/x/crypto     // Cryptographic primitives
aead.dev/minisign       // Minisign implementation
```

## Build Instructions

```bash
nix-shell . --run "go build ./cmd/..."
nix-shell . --run "go test ./..."
```

## File Structure

```
cmd/
  duplicate/main.go       # Import keys from mnemonic to YubiKey
  mnemonic/main.go        # Generate BIP39 mnemonic
  yubisign/main.go        # YubiKey signing tool
extra/
  age-plugin-yubi25519/   # Age plugin
internal/
  age/                   # Age encryption
  bech32/                # Bech32 encoding
  crypto/                # Key derivation
  format/                # Age format
  minisign/              # Minisign wrapper
  yubi25519/             # Age identity implementation
  yubikey/               # YubiKey utilities
```

## Usage

### Generate Mnemonic

```bash
# Generate 24-word mnemonic (default)
./mnemonic

# Generate 12-word mnemonic
./mnemonic -words 12
```

### Duplicate YubiKey

```bash
# Read mnemonic from stdin only (never CLI to avoid bash history)
./duplicate < mnemonic.txt

# Or with pipe (will prompt for PIN)
cat mnemonic.txt | ./duplicate
```

### Sign with YubiKey

```bash
# Generate identity
./yubisign -G -s key.sec -p key.pub

# Sign a file
./yubisign -S -s key.sec -m file.txt

# Verify
./yubisign -V -p key.pub -m file.txt -x file.txt.sig
```
