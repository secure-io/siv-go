// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
)

// NewGCM returns a cipher.AEAD implementing the AES-GCM-SIV
// construction. The key must be either 16 or 32 bytes long.
func NewGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(key) == 24 { // Disallow 192 bit keys
		return nil, aes.KeySizeError(len(key))
	}
	return &aesGcmSiv{block: block, keyLen: len(key)}, nil
}

var _ cipher.AEAD = (*aesGcmSiv)(nil)

type aesGcmSiv struct {
	block  cipher.Block
	keyLen int
}

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

	ret, ciphertext := sliceForAppend(dst, len(plaintext)+16)
	encKey, authKey := c.deriveKeys(nonce)

	var tag [16]byte
	polyvalGeneric(&tag, additionalData, plaintext, authKey)
	for i := range nonce {
		tag[i] ^= nonce[i]
	}
	tag[15] &= 0x7f

	block, _ := aes.NewCipher(encKey)
	block.Encrypt(tag[:], tag[:])
	ctrBlock := tag
	ctrBlock[15] |= 0x80

	xorKeystreamGeneric(ciphertext, plaintext, encKey, ctrBlock[:])
	copy(ciphertext[len(plaintext):], tag[:])
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

	tag := ciphertext[len(ciphertext)-c.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-c.Overhead()]
	ret, plaintext := sliceForAppend(dst, len(ciphertext))

	encKey, authKey := c.deriveKeys(nonce)
	var ctrBlock [16]byte
	copy(ctrBlock[:], tag)
	ctrBlock[15] |= 0x80
	xorKeystreamGeneric(plaintext, ciphertext, encKey, ctrBlock[:])

	var sum [16]byte
	polyvalGeneric(&sum, additionalData, plaintext, authKey)
	for i := range nonce {
		sum[i] ^= nonce[i]
	}
	sum[15] &= 0x7f

	block, _ := aes.NewCipher(encKey)
	block.Encrypt(sum[:], sum[:])
	if subtle.ConstantTimeCompare(sum[:], tag[:]) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}

func (c *aesGcmSiv) deriveKeys(nonce []byte) (encKey, authKey []byte) {
	var counter [16]byte
	encKey = make([]byte, 32)
	authKey = make([]byte, 16)
	copy(counter[4:], nonce[:])

	var tmp [16]byte
	binary.LittleEndian.PutUint32(counter[:4], 0)
	c.block.Encrypt(tmp[:], counter[:])
	copy(authKey[0:], tmp[:8])

	binary.LittleEndian.PutUint32(counter[:4], 1)
	c.block.Encrypt(tmp[:], counter[:])
	copy(authKey[8:], tmp[:8])

	binary.LittleEndian.PutUint32(counter[:4], 2)
	c.block.Encrypt(tmp[:], counter[:])
	copy(encKey[0:], tmp[:8])

	binary.LittleEndian.PutUint32(counter[:4], 3)
	c.block.Encrypt(tmp[:], counter[:])
	copy(encKey[8:], tmp[:8])

	if c.keyLen == 16 {
		return encKey[:16], authKey
	}

	binary.LittleEndian.PutUint32(counter[:4], 4)
	c.block.Encrypt(tmp[:], counter[:])
	copy(encKey[16:], tmp[:8])

	binary.LittleEndian.PutUint32(counter[:4], 5)
	c.block.Encrypt(tmp[:], counter[:])
	copy(encKey[24:], tmp[:8])

	return encKey, authKey
}
