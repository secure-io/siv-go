// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package siv

import (
	"crypto/subtle"
	"hash"

	cmac "github.com/aead/cmac/aes"
	"golang.org/x/sys/cpu"
)

func aesCMacXORKeyStream(dst, src, iv, keys []byte, keyLen uint64)

func newCMAC(key []byte) aead {
	if cpu.X86.HasAES {
		cmac, _ := cmac.New(key[:len(key)/2])
		key = key[len(key)/2:]
		keys := make([]byte, 4*(28+len(key)))
		keySchedule(keys, key)
		return &aesSivCMacAsm{
			cmac:      cmac,
			keys:      keys,
			keyLength: len(key),
		}
	}
	return newCMACGeneric(key)
}

type aesSivCMacAsm struct {
	cmac      hash.Hash
	keys      []byte
	keyLength int
}

func (c *aesSivCMacAsm) seal(ciphertext, nonce, plaintext, additionalData []byte) {
	v := s2vGeneric(additionalData, nonce, plaintext, c.cmac)
	copy(ciphertext, v[:])
	ciphertext = ciphertext[len(v):]

	iv := newIV(v)
	aesCMacXORKeyStream(ciphertext, plaintext, iv[:], c.keys, uint64(c.keyLength))
}

func (c *aesSivCMacAsm) open(plaintext, nonce, ciphertext, additionalData []byte) error {
	var v [16]byte
	copy(v[:], ciphertext)
	ciphertext = ciphertext[len(v):]

	iv := newIV(v)
	aesCMacXORKeyStream(plaintext, ciphertext, iv[:], c.keys, uint64(c.keyLength))

	tag := s2vGeneric(additionalData, nonce, plaintext, c.cmac)
	if subtle.ConstantTimeCompare(v[:], tag[:]) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return errOpen
	}
	return nil
}
