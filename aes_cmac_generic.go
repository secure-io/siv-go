// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"hash"

	cmac "github.com/aead/cmac/aes"
)

func newCMACGeneric(key []byte) authEnc {
	cmac, _ := cmac.New(key[:len(key)/2])
	block, _ := aes.NewCipher(key[len(key)/2:])
	return &aesSivCMacGeneric{cmac: cmac, block: block}
}

type aesSivCMacGeneric struct {
	cmac  hash.Hash
	block cipher.Block
}

func (c *aesSivCMacGeneric) Seal(ciphertext, nonce, plaintext, additionalData []byte) {
	v := c.s2v(additionalData, nonce, plaintext)
	copy(ciphertext, v[:])

	iv := newIV(v)
	ctr := cipher.NewCTR(c.block, iv[:])
	ctr.XORKeyStream(ciphertext[len(v):], plaintext)
}

func (c *aesSivCMacGeneric) Open(plaintext, nonce, ciphertext, additionalData []byte) error {
	var tag [16]byte
	copy(tag[:], ciphertext[:16])
	ciphertext = ciphertext[16:]

	iv := newIV(tag)
	ctr := cipher.NewCTR(c.block, iv[:])
	ctr.XORKeyStream(plaintext, ciphertext)

	v := c.s2v(additionalData, nonce, plaintext)
	if subtle.ConstantTimeCompare(v[:], tag[:]) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return errOpen
	}
	return nil
}

func (c *aesSivCMacGeneric) s2v(additionalData, nonce, plaintext []byte) [16]byte {
	var b0, b1 [16]byte
	c.cmac.Write(b0[:])
	c.cmac.Sum(b1[:0])
	c.cmac.Reset()

	if len(additionalData) > 0 || len(nonce) > 0 {
		c.cmac.Write(additionalData)
		c.cmac.Sum(b0[:0])
		c.cmac.Reset()

		dbl(&b1)
		for i := range b1 {
			b1[i] ^= b0[i]
		}
		if len(nonce) > 0 {
			c.cmac.Write(nonce)
			c.cmac.Sum(b0[:0])
			c.cmac.Reset()

			dbl(&b1)
			for i := range b1 {
				b1[i] ^= b0[i]
			}
		}
		for i := range b0 {
			b0[i] = 0
		}
	}

	if len(plaintext) >= 16 {
		n := len(plaintext) - 16
		copy(b0[:], plaintext[n:])
		c.cmac.Write(plaintext[:n])
	} else {
		copy(b0[:], plaintext)
		b0[len(plaintext)] = 0x80
		dbl(&b1)
	}

	for i := range b0 {
		b0[i] ^= b1[i]
	}
	c.cmac.Write(b0[:])
	c.cmac.Sum(b0[:0])
	c.cmac.Reset()
	return b0
}

func newIV(v [16]byte) [16]byte {
	v[8] &= 0x7f
	v[12] &= 0x7f
	return v
}

func dbl(b *[16]byte) {
	var z byte
	for i := 15; i >= 0; i-- {
		zz := b[i] >> 7
		b[i] = b[i]<<1 | z
		z = zz
	}
	b[15] ^= byte(subtle.ConstantTimeSelect(int(z), 0x87, 0))
}
