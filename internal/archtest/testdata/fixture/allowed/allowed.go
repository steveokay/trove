// Package allowed stands in for the single package a quarantine rule exempts.
// It imports the same primitives as package aead and must not be reported.
package allowed

import (
	"crypto/aes"
	"crypto/cipher"
)

// Block builds a cipher, which is this package's job.
func Block(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }
