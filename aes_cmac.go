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

// NewCMAC returns a new cipher.AEAD implementing AES-SIV-CMAC
// as descirbed in RFC 5297. The key must be twice as large as
// an AES key - so either 256, 384 or 512 bit.
//
// NewCMAC differs from other cipher.AEAD implementations such
// that the nonce may be empty or NonceSize() bytes long.
// AES-SIV-CMAC is an determinist AEAD if no unique/random nonce
// is provided.
func NewCMAC(key []byte) (cipher.AEAD, error) {
	mac, err := cmac.New(key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	ctrBlock, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
	return &aesSivCMac{
		cmac: mac,
		ctr:  &aesCtr{block: ctrBlock},
	}, nil
}

// aesSivCMac implements the AES-SIV using the AES-CMAC as
// pseudo-random function.
type aesSivCMac struct {
	cmac hash.Hash
	ctr  ctrMode
}

func (c *aesSivCMac) NonceSize() int { return aes.BlockSize }

func (c *aesSivCMac) Overhead() int { return aes.BlockSize }

func (c *aesSivCMac) Seal(dst, plaintext, nonce, additionalData []byte) []byte {
	if n := len(nonce); n != 0 && n != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-SIV-CMAC")
	}
	v := c.s2v(additionalData, nonce, plaintext)
	ret, out := sliceForAppend(dst, 16+len(plaintext))
	copy(out, v[:])

	iv := newIV(v)
	c.ctr.Reset(iv[:])
	c.ctr.XORKeyStream(out[16:], plaintext)
	return ret
}

func (c *aesSivCMac) Open(dst, ciphertext, nonce, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != 0 && n != c.NonceSize() {
		panic("siv: incorrect nonce length given to AES-SIV-CMAC")
	}
	var tag [16]byte
	copy(tag[:], ciphertext[:16])
	ciphertext = ciphertext[16:]

	iv := newIV(tag)
	c.ctr.Reset(iv[:])

	ret, out := sliceForAppend(dst, len(ciphertext))
	c.ctr.XORKeyStream(out, ciphertext)
	v := c.s2v(additionalData, nonce, out)

	if subtle.ConstantTimeCompare(v[:], tag[:]) != 1 {
		for i := range out {
			out[i] = 0
		}
		return ret, errOpen
	}
	return ret, nil
}

func (c *aesSivCMac) s2v(additionalData, nonce, plaintext []byte) [16]byte {
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

var _ (ctrMode) = (*aesCtr)(nil)

type ctrMode interface {
	cipher.Stream

	Reset(iv []byte)
}

type aesCtr struct {
	block cipher.Block
	ctr   cipher.Stream
}

func (c *aesCtr) XORKeyStream(dst, src []byte) { c.ctr.XORKeyStream(dst, src) }
func (c *aesCtr) Reset(iv []byte)              { c.ctr = cipher.NewCTR(c.block, iv) }
