// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

#include "textflag.h"
#include "aes_macros_amd64.s"

DATA ·one<>+0x00(SB)/8, $1
DATA ·one<>+0x08(SB)/8, $0
GLOBL ·one<>(SB), (NOPTR+RODATA), $16

DATA ·polyvalMask<>+0x00(SB)/8, $0x0000000000000001
DATA ·polyvalMask<>+0x08(SB)/8, $0xc200000000000000
GLOBL ·polyvalMask<>(SB), (NOPTR+RODATA), $16

// func aesGcmXORKeyStream(dst, src, iv, keys []byte, keyLen uint64)
TEXT ·aesGcmXORKeyStream(SB), 4, $0-104
	MOVQ dst+0(FP), DI
	MOVQ src+24(FP), SI
	MOVQ src_len+32(FP), DX
	MOVQ iv+48(FP), BX
	MOVQ keys+72(FP), AX
	MOVQ keyLen+96(FP), CX

	TESTQ DX, DX
	JZ    return

	MOVUPS (0 * 16)(BX), X10
	MOVUPS ·one<>(SB), X9

	CMPQ DX, $64
	JB   loop_1
	CMPQ DX, $128
	JB   loop_4

loop_8:
	MOVAPS X10, X0
	PADDD  X9, X10
	MOVAPS X10, X1
	PADDD  X9, X10
	MOVAPS X10, X2
	PADDD  X9, X10
	MOVAPS X10, X3
	PADDD  X9, X10
	MOVAPS X10, X4
	PADDD  X9, X10
	MOVAPS X10, X5
	PADDD  X9, X10
	MOVAPS X10, X6
	PADDD  X9, X10
	MOVAPS X10, X7
	PADDD  X9, X10

	CMPQ CX, $16
	JE   aes_128_8

aes_256_8:
	AES_256_8(X0, X1, X2, X3, X4, X5, X6, X7, X8, AX)
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
	MOVAPS X10, X0
	PADDD  X9, X10
	MOVAPS X10, X1
	PADDD  X9, X10
	MOVAPS X10, X2
	PADDD  X9, X10
	MOVAPS X10, X3
	PADDD  X9, X10

	CMPQ CX, $16
	JE   aes_128_4

aes_256_4:
	AES_256_4(X0, X1, X2, X3, X4, AX)
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
	MOVAPS X10, X0
	PADDD  X9, X10
	CMPQ   CX, $16
	JE     aes_128_1

aes_256_1:
	AES_256(X0, X1, AX)
	JMP xor_1

aes_128_1:
	AES_128(X0, X1, AX)

xor_1:
	CMPQ   DX, $16
	JB     finalize
	PXOR   0(SI), X0
	MOVUPS X0, 0(DI)

	ADDQ $16, SI
	ADDQ $16, DI
	SUBQ $16, DX
	JMP  loop_1

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

// func polyval(tag *[16]byte, additionalData, plaintext, key []byte)
TEXT ·polyval(SB), $0-64
	MOVQ tag+0(FP), DI
	MOVQ additionalData+8(FP), SI
	MOVQ additionalData_len+16(FP), DX
	MOVQ plaintext+32(FP), BX
	MOVQ plaintext_len+40(FP), CX
	MOVQ key+56(FP), AX

	MOVQ  DX, R14
	MOVQ  CX, R15
	SHLQ  $3, R14
	SHLQ  $3, R15
	MOVOU 0(DI), X0
	MOVOU 0(AX), X1
	MOVOU ·polyvalMask<>(SB), X2

	MOVQ $2, AX

loop:
	CMPQ   DX, $16
	JB     finalize
	MOVUPS 0(SI), X7
	PXOR   X7, X0
	MULTIPLY(X0, X1, X2, X3, X4, X5, X6)
	ADDQ   $16, SI
	SUBQ   $16, DX
	JMP    loop

finalize:
	TESTQ DX, DX
	JZ    process_next
	MOVQ  DI, R11
	PXOR  X3, X3
	MOVOU X3, 0(R11)

finalize_loop:
	MOVB 0(SI), R10
	MOVB R10, 0(R11)
	INCQ SI
	INCQ R11
	DECQ DX
	JNZ  finalize_loop
	PXOR 0(DI), X0
	MULTIPLY(X0, X1, X2, X3, X4, X5, X6)

process_next:
	MOVQ BX, SI
	MOVQ CX, DX
	DECQ AX
	JNZ  loop

	MOVQ  R14, 0(DI)
	MOVQ  R15, 8(DI)
	PXOR  0(DI), X0
	MULTIPLY(X0, X1, X2, X3, X4, X5, X6)
	MOVOU X0, 0(DI)
	RET
