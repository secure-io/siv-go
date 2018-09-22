// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"

	"golang.org/x/sys/cpu"
)

func polyval(tag *[16]byte, additionalData, plaintext, key []byte)

func aesGcmXORKeyStream(dst, src, iv, keys []byte, keyLen uint64)

func newGCM(key []byte) aead {
	if cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ {
		block, _ := aes.NewCipher(key)
		return &aesGcmSivAsm{block: block, keyLen: len(key)}
	}
	return newGCMGeneric(key)
}

var _ aead = (*aesGcmSivAsm)(nil)

type aesGcmSivAsm struct {
	block  cipher.Block
	keyLen int
}

func (c *aesGcmSivAsm) seal(ciphertext, nonce, plaintext, additionalData []byte) {
	encKey, authKey := deriveKeys(nonce, c.block, c.keyLen)

	var tag [16]byte
	polyval(&tag, additionalData, plaintext, authKey)
	for i := range nonce {
		tag[i] ^= nonce[i]
	}
	tag[15] &= 0x7f

	var encKeys [240]byte
	keySchedule(encKeys[:], encKey)
	encryptBlock(tag[:], tag[:], encKeys[:], uint64(len(encKey)))
	ctrBlock := tag
	ctrBlock[15] |= 0x80

	aesGcmXORKeyStream(ciphertext, plaintext, ctrBlock[:], encKeys[:], uint64(len(encKey)))
	copy(ciphertext[len(plaintext):], tag[:])
}

func (c *aesGcmSivAsm) open(plaintext, nonce, ciphertext, additionalData []byte) error {
	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	encKey, authKey := deriveKeys(nonce, c.block, c.keyLen)
	var ctrBlock [16]byte
	copy(ctrBlock[:], tag)
	ctrBlock[15] |= 0x80

	var encKeys [240]byte
	keySchedule(encKeys[:], encKey)
	aesGcmXORKeyStream(plaintext, ciphertext, ctrBlock[:], encKeys[:], uint64(len(encKey)))

	var sum [16]byte
	polyval(&sum, additionalData, plaintext, authKey)
	for i := range nonce {
		sum[i] ^= nonce[i]
	}
	sum[15] &= 0x7f

	encryptBlock(sum[:], sum[:], encKeys[:], uint64(len(encKey)))
	if subtle.ConstantTimeCompare(sum[:], tag[:]) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return errOpen
	}
	return nil
}
