// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package siv

import (
	"crypto/aes"
	"encoding/binary"
)

func xorKeystreamGeneric(dst, src, key, iv []byte) {
	var ctr, tmp [16]byte
	copy(ctr[:], iv)
	counter := binary.LittleEndian.Uint32(ctr[:])
	block, _ := aes.NewCipher(key)
	for len(src) >= 16 {
		block.Encrypt(tmp[:], ctr[:])
		for i := range tmp {
			dst[i] = src[i] ^ tmp[i]
		}
		counter++
		binary.LittleEndian.PutUint32(ctr[:], counter)
		dst, src = dst[16:], src[16:]
	}
	if len(src) > 0 {
		block.Encrypt(tmp[:], ctr[:])
		for i := range src {
			dst[i] = src[i] ^ tmp[i]
		}
	}
}

type fieldElement = [2]uint64

func polyvalGeneric(tag *[16]byte, additionalData, plaintext, key []byte) {
	var (
		r fieldElement
		h = fieldElement{
			binary.LittleEndian.Uint64(key[0:]),
			binary.LittleEndian.Uint64(key[8:]),
		}
		addLen = 8 * uint64(len(additionalData))
		ptLen  = 8 * uint64(len(plaintext))
	)
	for len(additionalData) >= 16 {
		r[0] ^= binary.LittleEndian.Uint64(additionalData)
		r[1] ^= binary.LittleEndian.Uint64(additionalData[8:])
		multiply(&r, &h)
		additionalData = additionalData[16:]
	}
	if len(additionalData) > 0 {
		var buffer [16]byte
		copy(buffer[:], additionalData)
		r[0] ^= binary.LittleEndian.Uint64(buffer[0:])
		r[1] ^= binary.LittleEndian.Uint64(buffer[8:])
		multiply(&r, &h)
	}
	for len(plaintext) >= 16 {
		r[0] ^= binary.LittleEndian.Uint64(plaintext)
		r[1] ^= binary.LittleEndian.Uint64(plaintext[8:])
		multiply(&r, &h)
		plaintext = plaintext[16:]
	}
	if len(plaintext) > 0 {
		var buffer [16]byte
		copy(buffer[:], plaintext)
		r[0] ^= binary.LittleEndian.Uint64(buffer[0:])
		r[1] ^= binary.LittleEndian.Uint64(buffer[8:])
		multiply(&r, &h)
	}
	r[0] ^= addLen
	r[1] ^= ptLen
	multiply(&r, &h)
	binary.LittleEndian.PutUint64(tag[0:], r[0])
	binary.LittleEndian.PutUint64(tag[8:], r[1])
}

func multiply(r, h *fieldElement) {
	const (
		polyvalMask = 0xc200000000000000
		lowMask     = 0x00000000ffffffff
		highMask    = 0xffffffff00000000
	)
	var t00, t01, t10, t11, t20, t21, t30, t31 uint64

	t00, t01 = umul64(r[0], h[0])
	t10, t11 = umul64(r[1], h[0])
	t20, t21 = umul64(r[0], h[1])
	t30, t31 = umul64(r[1], h[1])
	t10 ^= t20
	t11 ^= t21
	t20 = 0
	t21 = t10
	t10 = t11
	t11 = 0
	t01 ^= t21
	t30 ^= t10

	t10, t11 = umul64(polyvalMask, t00)
	t20 = (t01 & lowMask) | (t01 & highMask)
	t21 = (t00 & lowMask) | (t00 & highMask)
	t00 = t10 ^ t20
	t01 = t11 ^ t21

	t10, t11 = umul64(polyvalMask, t00)
	t20 = (t01 & lowMask) | (t01 & highMask)
	t21 = (t00 & lowMask) | (t00 & highMask)
	t00 = t10 ^ t20
	t01 = t11 ^ t21

	r[0] = t30 ^ t00
	r[1] = t31 ^ t01
}

func umul64(src1, src2 uint64) (d0, d1 uint64) {
	const (
		one  uint64 = 1
		mask uint64 = one << 63
	)
	for i := uint(0); i < 64; i++ {
		d1 ^= ^((src2 & (one << i) >> i) - 1) & src1
		d0 = d0 >> 1
		d0 ^= ^((d1 & one) - 1) & mask
		d1 = d1 >> 1
	}
	return
}
