// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build !amd64 gccgo appengine

package siv

type aesSivCMacImpl = aesSivCMacGeneric

func newCMAC(key []byte) aead { return newCMACGeneric(key) }
