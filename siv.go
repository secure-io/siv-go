// Package siv implements the Synthetic Initialization Vector (SIV)
// authenticated encryption scheme specified in [RFC 5297](https://tools.ietf.org/html/rfc5297)
//
// It provides an crypto/cipher.AEAD compatable API. However, the
// nonce may be omitted making AES-SIV a deterministic encryption
// scheme.
package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"

	cmac "github.com/aead/cmac/aes"
)

var errOpen = errors.New("siv: message authentication failed")

// NewAES returns a new AES-SIV cipher using CMAC as PRF
// and message authentication code. The key must be twice
// as large as an AES key - so 256, 384 or 512 bit.
//
// It returns an error if the key is not twice as large
// as an valid AES key.
//
// The AEAD nonce used for Seal/Open must be either 0 or 16
// bytes long.
func NewAES(key []byte) (cipher.AEAD, error) { return NewAESWithNonceSize(key, 16) }

// WithNonceSize returns a new AES-SIV cipher using CMAC as PRF
// and message authentication code. The key must be twice
// as large as an AES key - so 256, 384 or 512 bit.
//
// It returns an error if the key is not twice as large
// as an valid AES key.
//
// The AEAD nonce used for Seal/Open must be either 0 or size
// bytes long.
func NewAESWithNonceSize(key []byte, size int) (cipher.AEAD, error) {
	mac, err := cmac.New(key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	ctrBlock, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
	return &aesSIV{
		cmac:      mac,
		ctr:       &aesCtr{block: ctrBlock},
		nonceSize: size,
	}, nil
}

// aesSIV implements the AES-SIV using the AES-CMAC as
// pseudo-random function.
type aesSIV struct {
	cmac      hash.Hash
	ctr       ctrMode
	nonceSize int
}

func (c *aesSIV) NonceSize() int { return c.nonceSize }

func (c *aesSIV) Overhead() int { return aes.BlockSize }

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be 0 or NonceSize() bytes long and my be unique
// for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (c *aesSIV) Seal(dst, plaintext, nonce, additionalData []byte) []byte {
	if n := len(nonce); n != 0 && n != c.nonceSize {
		panic("siv: incorrect nonce length given to AES-SIV")
	}
	v := c.s2v(additionalData, nonce, plaintext)
	ret, out := sliceForAppend(dst, 16+len(plaintext))
	copy(out, v[:])

	iv := newIV(v)
	c.ctr.Reset(iv[:])
	c.ctr.XORKeyStream(out[16:], plaintext)
	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be 0 or NonceSize()
// bytes long and both it and the additional data must match the value
// passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (c *aesSIV) Open(dst, ciphertext, nonce, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != 0 && n != c.nonceSize {
		panic("siv: incorrect nonce length given to AES-SIV")
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

func (c *aesSIV) s2v(additionalData, nonce, plaintext []byte) [16]byte {
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

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
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
