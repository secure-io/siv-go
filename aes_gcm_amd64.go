// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package siv

import (
	"golang.org/x/sys/cpu"
)

func newGCM(key []byte) authEnc {
	if cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ {
	}
	return newGCMGeneric(key)
}
