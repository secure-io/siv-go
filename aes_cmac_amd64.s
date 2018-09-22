// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

#include "aes_macros_amd64.s"

#define LOAD_COUNTER(C, c0, c1, T) \
	MOVQ   c0, C; \
	MOVQ   c1, T; \
	PSLLDQ $8, T; \
	PXOR   T, C

#define INC_COUNTER(c0, c1) \
	BSWAPQ c1;     \
	BSWAPQ c0;     \
	ADDQ   $1, c1; \
	ADCQ   $0, c0; \
	BSWAPQ c1;     \
	BSWAPQ c0

// func aesCMacXORKeyStream(dst, src, iv, keys []byte, keyLen uint64)
TEXT ·aesCMacXORKeyStream(SB), 4, $0-104
	MOVQ dst+0(FP), DI
	MOVQ src+24(FP), SI
	MOVQ src_len+32(FP), DX
	MOVQ iv+48(FP), BX
	MOVQ keys+72(FP), AX
	MOVQ keyLen+96(FP), CX

	TESTQ DX, DX
	JZ    return

	MOVQ 0(BX), R8
	MOVQ 8(BX), R9

	CMPQ DX, $64
	JB   loop_1
	CMPQ DX, $128
	JB   loop_4

loop_8:
	LOAD_COUNTER(X0, R8, R9, X8)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X1, R8, R9, X8)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X2, R8, R9, X8)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X3, R8, R9, X8)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X4, R8, R9, X8)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X5, R8, R9, X8)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X6, R8, R9, X8)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X7, R8, R9, X8)
	INC_COUNTER(R8, R9)

	CMPQ CX, $24
	JE   aes_192_8
	JB   aes_128_8

aes_256_8:
	AES_256_8(X0, X1, X2, X3, X4, X5, X6, X7, X8, AX)
	JMP xor_8

aes_192_8:
	AES_192_8(X0, X1, X2, X3, X4, X5, X6, X7, X8, AX)
	JMP xor_8

aes_128_8:
	AES_128_8(X0, X1, X2, X3, X4, X5, X6, X7, X8, AX)

xor_8:
	PXOR   (0 * 16)(SI), X0
	PXOR   (1 * 16)(SI), X1
	PXOR   (2 * 16)(SI), X2
	PXOR   (3 * 16)(SI), X3
	PXOR   (4 * 16)(SI), X4
	PXOR   (5 * 16)(SI), X5
	PXOR   (6 * 16)(SI), X6
	PXOR   (7 * 16)(SI), X7
	MOVUPS X0, (0 * 16)(DI)
	MOVUPS X1, (1 * 16)(DI)
	MOVUPS X2, (2 * 16)(DI)
	MOVUPS X3, (3 * 16)(DI)
	MOVUPS X4, (4 * 16)(DI)
	MOVUPS X5, (5 * 16)(DI)
	MOVUPS X6, (6 * 16)(DI)
	MOVUPS X7, (7 * 16)(DI)
	ADDQ   $128, SI
	ADDQ   $128, DI
	SUBQ   $128, DX
	CMPQ   DX, $128
	JAE    loop_8
	TESTQ  DX, DX
	JZ     return
	CMPQ   DX, $64
	JB     loop_1

loop_4:
	LOAD_COUNTER(X0, R8, R9, X4)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X1, R8, R9, X4)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X2, R8, R9, X4)
	INC_COUNTER(R8, R9)
	LOAD_COUNTER(X3, R8, R9, X4)
	INC_COUNTER(R8, R9)

	CMPQ CX, $24
	JE   aes_192_4
	JB   aes_128_4

aes_256_4:
	AES_256_4(X0, X1, X2, X3, X4, AX)
	JMP xor_4

aes_192_4:
	AES_192_4(X0, X1, X2, X3, X4, AX)
	JMP xor_4

aes_128_4:
	AES_128_4(X0, X1, X2, X3, X4, AX)

xor_4:
	PXOR   (0 * 16)(SI), X0
	PXOR   (1 * 16)(SI), X1
	PXOR   (2 * 16)(SI), X2
	PXOR   (3 * 16)(SI), X3
	MOVUPS X0, (0 * 16)(DI)
	MOVUPS X1, (1 * 16)(DI)
	MOVUPS X2, (2 * 16)(DI)
	MOVUPS X3, (3 * 16)(DI)
	ADDQ   $64, SI
	ADDQ   $64, DI
	SUBQ   $64, DX
	CMPQ   DX, $64
	JAE    loop_4
	TESTQ  DX, DX
	JZ     return

loop_1:
	LOAD_COUNTER(X0, R8, R9, X1)
	CMPQ CX, $24
	JE   aes_192_1
	JB   aes_128_1

aes_256_1:
	AES_256(X0, X1, AX)
	JMP xor_1

aes_192_1:
	AES_192(X0, X1, AX)
	JMP xor_1

aes_128_1:
	AES_128(X0, X1, AX)

xor_1:
	CMPQ   DX, $16
	JB     finalize
	PXOR   0(SI), X0
	MOVUPS X0, 0(DI)
	INC_COUNTER(R8, R9)
	ADDQ   $16, SI
	ADDQ   $16, DI
	SUBQ   $16, DX
	JMP    loop_1

finalize:
	TESTQ DX, DX
	JZ    return

finalize_loop:
	MOVQ   X0, R10
	PSRLDQ $1, X0
	MOVB   0(SI), R11
	XORQ   R11, R10
	MOVB   R10, 0(DI)
	INCQ   SI
	INCQ   DI
	DECQ   DX
	JNZ    finalize_loop

return:
	RET
