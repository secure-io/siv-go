// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package siv

import (
	"crypto/aes"
	"crypto/cipher"
)

// NewCMAC returns a cipher.AEAD implementing AES-SIV-CMAC
// as specified in RFC 5297. The key must be twice as large
// as an AES key - so either 32, 48 or 64 bytes long.
//
// The returned cipher.AEAD accepts an empty or NonceSize()
// bytes long nonce.
func NewCMAC(key []byte) (cipher.AEAD, error) {
	if k := len(key); k != 32 && k != 48 && k != 64 {
		return nil, aes.KeySizeError(k)
	}
	return &aesSivCMac{newCMAC(key)}, nil
}

type aesSivCMac struct{ aead }

func (c *aesSivCMac) NonceSize() int { return aes.BlockSize }

func (c *aesSivCMac) Overhead() int { return aes.BlockSize }

func (c *aesSivCMac) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != 0 && n != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-SIV-CMAC")
	}
	ret, ciphertext := sliceForAppend(dst, c.Overhead()+len(plaintext))
	c.seal(ciphertext, nonce, plaintext, additionalData)
	return ret
}

func (c *aesSivCMac) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != 0 && n != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-SIV-CMAC")
	}
	if len(ciphertext) < c.Overhead() {
		return dst, errOpen
	}
	ret, plaintext := sliceForAppend(dst, len(ciphertext)-c.Overhead())
	if err := c.open(plaintext, nonce, ciphertext, additionalData); err != nil {
		return ret, err
	}
	return ret, nil
}
