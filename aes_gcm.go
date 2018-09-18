// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package siv

import (
	"crypto/aes"
	"crypto/cipher"
)

// NewGCM returns a cipher.AEAD implementing the AES-GCM-SIV
// construction. The key must be either 16 or 32 bytes long.
func NewGCM(key []byte) (cipher.AEAD, error) {
	if k := len(key); k != 16 && k != 32 {
		return nil, aes.KeySizeError(k)
	}
	return &aesGcmSiv{newGCM(key)}, nil
}

var _ cipher.AEAD = (*aesGcmSiv)(nil)

type aesGcmSiv struct{ aead }

func (c *aesGcmSiv) NonceSize() int { return 12 }

func (c *aesGcmSiv) Overhead() int { return aes.BlockSize }

func (c *aesGcmSiv) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-GCM-SIV")
	}
	if uint64(len(plaintext)) > 1<<36 {
		panic("siv: plaintext too large for AES-GCM-SIV")
	}
	if uint64(len(additionalData)) > 1<<36 {
		panic("siv: additional data too large for AES-GCM-SIV")
	}
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+c.Overhead())
	c.seal(ciphertext, nonce, plaintext, additionalData)
	return ret
}

func (c *aesGcmSiv) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-GCM-SIV")
	}
	if uint64(len(ciphertext)) > (1<<36)+uint64(c.Overhead()) {
		panic("siv: ciphertext too large for AES-GCM-SIV")
	}
	if uint64(len(additionalData)) > 1<<36 {
		panic("siv: additional data too large for AES-GCM-SIV")
	}
	if len(ciphertext) < c.Overhead() {
		return nil, errOpen
	}
	ret, plaintext := sliceForAppend(dst, len(ciphertext)-c.Overhead())
	if err := c.open(plaintext, nonce, ciphertext, additionalData); err != nil {
		return ret, err
	}
	return ret, nil
}
