// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

#include "aes_macros_amd64.s"

// func keySchedule(keys []uint32, key []byte)
TEXT ·keySchedule(SB), 4, $0-48
	MOVQ keys+0(FP), AX
	MOVQ key+24(FP), BX
	MOVQ keyLen+32(FP), DX

	CMPQ DX, $24
	JE   aes_192
	JB   aes_128

aes_256:
	MOVUPS (0 * 16)(BX), X0
	MOVUPS (1 * 16)(BX), X1
	AES_KEY_SCHEDULE_256(AX, X0, X1, X2, X3)
	JMP    return

aes_192:
	MOVUPS (0 * 16)(BX), X0
	MOVQ   (1 * 16)(BX), X1
	AES_KEY_SCHEDULE_192(AX, X0, X1, X2, X3, X4, X5, X6)
	JMP    return

aes_128:
	MOVUPS (0 * 16)(BX), X0
	AES_KEY_SCHEDULE_128(AX, X0, X1, X2)

return:
	RET

// func encryptBlock(dst, src, keys []byte, keyLen uint64)
TEXT ·encryptBlock(SB), 4, $0-80
	MOVQ dst+0(FP), DI
	MOVQ src+24(FP), SI
	MOVQ keys+48(FP), AX
	MOVQ keyLen+72(FP), DX

	MOVUPS (0 * 16)(SI), X0
	CMPQ   DX, $24
	JE     aes_192
	JB     aes_128

aes_256:
	AES_256(X0, X1, AX)
	JMP return

aes_192:
	AES_192(X0, X1, AX)
	JMP return

aes_128:
	AES_128(X0, X1, AX)

return:
	MOVUPS X0, (0 * 16)(DI)
	RET
