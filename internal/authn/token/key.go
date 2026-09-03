package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LoadOrCreateKey reads the Ed25519 signing key at path, generating one on
// the first run (ADR 0004: created beside the secrets key).
//
// An existing file that cannot be parsed is fatal and is never regenerated
// over: a fresh key would look like a successful start while quietly refusing
// every outstanding token and, worse, hiding that something rewrote the
// keyfile. The same rule as the secrets keyring (ADR 0016).
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseKey(path, raw)
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key.Seed()) + "\n"

	// O_EXCL: two racing first boots must not both think they wrote the key.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create signing key %s: %w", path, err)
	}
	if _, err := file.WriteString(encoded); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync signing key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close signing key: %w", err)
	}
	return key, nil
}

// parseKey decodes a keyfile: one base64 line holding the 32-byte seed. The
// permission check mirrors the secrets keyring's, including the Windows skip
// -- there are no POSIX bits there to check (Q25).
func parseKey(path string, raw []byte) (ed25519.PrivateKey, error) {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat signing key: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("signing key %s is readable beyond its owner (mode %v): anyone who reads it can mint tokens", path, fs.FileMode(info.Mode().Perm()))
		}
	}

	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("signing key %s is not base64: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key %s holds %d bytes, want a %d-byte seed", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
