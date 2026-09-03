// Package aead stands in for a package that reaches for the AEAD primitives
// directly instead of going through the one package allowed to hold them.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
)

// Block builds a cipher the caller has no business building here.
func Block(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }
