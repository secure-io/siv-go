// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package siv implements the Synthetic Initialization Vector (SIV)
// authenticated encryption scheme specified in [RFC 5297](https://tools.ietf.org/html/rfc5297)
//
// It provides an crypto/cipher.AEAD compatable API. However, the
// nonce may be omitted making AES-SIV a deterministic encryption
// scheme.
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
