// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package siv implements the Synthetic Initialization Vector (SIV)
// authenticated encryption scheme specified in RFC 5297.
//
//
// AES-SIV-CMAC
//
// AES-SIV-CMAC is a misuse-resistant AEAD scheme using AES-{128/192/256}
// for message privacy and integrity. In contrast to other AEAD schemes - like
// AES-GCM - AES-SIV-CMAC provides message integrity and message privacy
// (w.r.t the security of deterministic encryption) even if the nonce is reused
// or omitted at all.
// AES-SIV-CMAC creates a ciphertext which is 16 bytes longer than the plaintext.
// The ciphertext consists of the authentication tag (16 bytes) followed by the
// encrypted plaintext. For more details see [1].
//
//
// Deterministic AEAD
//
// Given the same plaintext and additional data a deterministic AEAD
// produces always the same ciphertext. Therefore it is not
// semantically secure. [2]
// However, any deterministic AEAD implemented by this package accepts
// a non-nil nonce making the encryption probabilistic. A deterministic
// AEAD which can be turned into a probabilistic AEAD using a nonce value
// is called misuse-resistant AEAD.
//
// [1] https://tools.ietf.org/html/rfc5297
// [2] https://en.wikipedia.org/wiki/Deterministic_encryption
package siv

import (
	"errors"
)

var errOpen = errors.New("siv: message authentication failed")

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
