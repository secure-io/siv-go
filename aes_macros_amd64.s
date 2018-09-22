// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64,!gccgo,!appengine

// MULTIPLY performs a GF multiplication using
// the irr. polynomial P. It computes R = H * R mod P
#define MULTIPLY(R, H, P, T0, T1, T2, T3) \
	MOVO      R, T0;        \
	MOVO      R, T1;        \
	MOVO      R, T2;        \
	MOVO      R, T3;        \
	PCLMULQDQ $0x00, H, T0; \
	PCLMULQDQ $0x10, H, T1; \
	PCLMULQDQ $0x01, H, T2; \
	PCLMULQDQ $0x11, H, T3; \
	PXOR      T2, T1;       \
	MOVO      T1, T2;       \
	PSLLDQ    $8, T2;       \
	PSRLDQ    $8, T1;       \
	PXOR      T2, T0;       \
	PXOR      T1, T3;       \
	MOVO      T0, T1;       \
	PCLMULQDQ $0x10, P, T1; \
	PSHUFD    $78, T0, T2;  \
	MOVO      T1, T0;       \
	PXOR      T2, T0;       \
	MOVO      T0, T1;       \
	PCLMULQDQ $0x10, P, T1; \
	PSHUFD    $78, T0, T2;  \
	MOVO      T1, T0;       \
	PXOR      T2, T0;       \
	MOVO      T3, R;        \
	PXOR      T0, R

#define AES_ROUND(OPCODE, t, k, keys, r) \
	MOVUPS (r * 16)(keys), k; \
	OPCODE k, t

#define AES_ROUND_4(OPCODE, t0, t1, t2, t3, k, keys, r) \
	MOVUPS (r * 16)(keys), k; \
	OPCODE k, t0;             \
	OPCODE k, t1;             \
	OPCODE k, t2;             \
	OPCODE k, t3

#define AES_ROUND_8(OPCODE, t0, t1, t2, t3, t4, t5, t6, t7, k, keys, r) \
	MOVUPS (r * 16)(keys), k; \
	OPCODE k, t0;             \
	OPCODE k, t1;             \
	OPCODE k, t2;             \
	OPCODE k, t3;             \
	OPCODE k, t4;             \
	OPCODE k, t5;             \
	OPCODE k, t6;             \
	OPCODE k, t7

#define AES_128(t, k, keys) \
	AES_ROUND(PXOR, t, k, keys, 0);       \
	AES_ROUND(AESENC, t, k, keys, 1);     \
	AES_ROUND(AESENC, t, k, keys, 2);     \
	AES_ROUND(AESENC, t, k, keys, 3);     \
	AES_ROUND(AESENC, t, k, keys, 4);     \
	AES_ROUND(AESENC, t, k, keys, 5);     \
	AES_ROUND(AESENC, t, k, keys, 6);     \
	AES_ROUND(AESENC, t, k, keys, 7);     \
	AES_ROUND(AESENC, t, k, keys, 8);     \
	AES_ROUND(AESENC, t, k, keys, 9);     \
	AES_ROUND(AESENCLAST, t, k, keys, 10)

#define AES_192(t, k, keys) \
	AES_ROUND(PXOR, t, k, keys, 0);       \
	AES_ROUND(AESENC, t, k, keys, 1);     \
	AES_ROUND(AESENC, t, k, keys, 2);     \
	AES_ROUND(AESENC, t, k, keys, 3);     \
	AES_ROUND(AESENC, t, k, keys, 4);     \
	AES_ROUND(AESENC, t, k, keys, 5);     \
	AES_ROUND(AESENC, t, k, keys, 6);     \
	AES_ROUND(AESENC, t, k, keys, 7);     \
	AES_ROUND(AESENC, t, k, keys, 8);     \
	AES_ROUND(AESENC, t, k, keys, 9);     \
	AES_ROUND(AESENC, t, k, keys, 10);    \
	AES_ROUND(AESENC, t, k, keys, 11);    \
	AES_ROUND(AESENCLAST, t, k, keys, 12)

#define AES_256(t, k, keys) \
	AES_ROUND(PXOR, t, k, keys, 0);       \
	AES_ROUND(AESENC, t, k, keys, 1);     \
	AES_ROUND(AESENC, t, k, keys, 2);     \
	AES_ROUND(AESENC, t, k, keys, 3);     \
	AES_ROUND(AESENC, t, k, keys, 4);     \
	AES_ROUND(AESENC, t, k, keys, 5);     \
	AES_ROUND(AESENC, t, k, keys, 6);     \
	AES_ROUND(AESENC, t, k, keys, 7);     \
	AES_ROUND(AESENC, t, k, keys, 8);     \
	AES_ROUND(AESENC, t, k, keys, 9);     \
	AES_ROUND(AESENC, t, k, keys, 10);    \
	AES_ROUND(AESENC, t, k, keys, 11);    \
	AES_ROUND(AESENC, t, k, keys, 12);    \
	AES_ROUND(AESENC, t, k, keys, 13);    \
	AES_ROUND(AESENCLAST, t, k, keys, 14)

#define AES_128_4(c0, c1, c2, c3, k, keys) \
	AES_ROUND_4(PXOR, c0, c1, c2, c3, k, keys, 0);       \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 1);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 2);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 3);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 4);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 5);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 6);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 7);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 8);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 9);     \
	AES_ROUND_4(AESENCLAST, c0, c1, c2, c3, k, keys, 10)

#define AES_192_4(c0, c1, c2, c3, k, keys) \
	AES_ROUND_4(PXOR, c0, c1, c2, c3, k, keys, 0);       \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 1);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 2);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 3);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 4);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 5);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 6);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 7);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 8);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 9);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 10);    \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 11);    \
	AES_ROUND_4(AESENCLAST, c0, c1, c2, c3, k, keys, 12)

#define AES_256_4(c0, c1, c2, c3, k, keys) \
	AES_ROUND_4(PXOR, c0, c1, c2, c3, k, keys, 0);       \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 1);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 2);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 3);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 4);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 5);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 6);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 7);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 8);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 9);     \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 10);    \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 11);    \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 12);    \
	AES_ROUND_4(AESENC, c0, c1, c2, c3, k, keys, 13);    \
	AES_ROUND_4(AESENCLAST, c0, c1, c2, c3, k, keys, 14)

#define AES_128_8(c0, c1, c2, c3, c4, c5, c6, c7, k, keys) \
	AES_ROUND_8(PXOR, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 0);       \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 1);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 2);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 3);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 4);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 5);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 6);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 7);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 8);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 9);     \
	AES_ROUND_8(AESENCLAST, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 10)

#define AES_192_8(c0, c1, c2, c3, c4, c5, c6, c7, k, keys) \
	AES_ROUND_8(PXOR, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 0);       \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 1);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 2);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 3);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 4);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 5);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 6);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 7);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 8);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 9);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 10);    \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 11);    \
	AES_ROUND_8(AESENCLAST, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 12)

#define AES_256_8(c0, c1, c2, c3, c4, c5, c6, c7, k, keys) \
	AES_ROUND_8(PXOR, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 0);       \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 1);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 2);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 3);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 4);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 5);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 6);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 7);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 8);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 9);     \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 10);    \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 11);    \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 12);    \
	AES_ROUND_8(AESENC, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 13);    \
	AES_ROUND_8(AESENCLAST, c0, c1, c2, c3, c4, c5, c6, c7, k, keys, 14)

#define EXPAND_KEY_128(keys, n, k1, k2, t) \
	PSHUFD $0xff, k2, k2;     \
	SHUFPS $0x10, k1, t;      \
	PXOR   t, k1;             \
	SHUFPS $0x8c, k1, t;      \
	PXOR   t, k1;             \
	PXOR   k2, k1;            \
	MOVUPS k1, (n * 16)(keys)

#define EXPAND_KEY_192_A(keys, n, k1, k2, k3, t0, t1, t2, t3) \
	PSHUFD $0x55, k2, k2;           \
	SHUFPS $0x10, k1, t0;           \
	PXOR   t0, k1;                  \
	SHUFPS $0x8c, k1, t0;           \
	PXOR   t0, k1;                  \
	PXOR   k2, k1;                  \
	MOVAPS k3, t1;                  \
	MOVAPS k3, t2;                  \
	PSLLDQ $0x4, t1;                \
	PSHUFD $0xff, k1, t3;           \
	PXOR   t3, k3;                  \
	PXOR   t1, k3;                  \
	MOVAPS k1, k2;                  \
	SHUFPS $0x44, k1, t2;           \
	SHUFPS $0x4e, k3, k2;           \
	MOVUPS t2, (n * 16)(keys);      \
	MOVUPS k2, ((n + 1) * 16)(keys)

#define EXPAND_KEY_192_B(keys, n, k1, k2, k3, t0, t1, t2) \
	PSHUFD $0x55, k2, k2;     \
	SHUFPS $0x10, k1, t0;     \
	PXOR   t0, k1;            \
	SHUFPS $0x8c, k1, t0;     \
	PXOR   t0, k1;            \
	PXOR   k2, k1;            \
	MOVAPS k3, t1;            \
	PSLLDQ $0x4, t1;          \
	PSHUFD $0xff, k1, t2;     \
	PXOR   t2, k3;            \
	PXOR   t1, k3;            \
	MOVUPS k1, (n * 16)(keys)

#define EXPAND_KEY_256(keys, n, k1, k2, t) \
	PSHUFD $0xaa, k2, k2;     \
	SHUFPS $0x10, k1, t;      \
	PXOR   t, k1;             \
	SHUFPS $0x8c, k1, t;      \
	PXOR   t, k1;             \
	PXOR   k2, k1;            \
	MOVUPS k1, (n * 16)(keys)

#define AES_KEY_SCHEDULE_128(keys, k, t0, t1) \
	PXOR            t1, t1;             \
	MOVUPS          k, (0 * 16)(keys);  \
	AESKEYGENASSIST $0x01, k, t0;       \
	EXPAND_KEY_128(keys, 1, k, t0, t1); \
	AESKEYGENASSIST $0x02, k, t0;       \
	EXPAND_KEY_128(keys, 2, k, t0, t1); \
	AESKEYGENASSIST $0x04, k, t0;       \
	EXPAND_KEY_128(keys, 3, k, t0, t1); \
	AESKEYGENASSIST $0x08, k, t0;       \
	EXPAND_KEY_128(keys, 4, k, t0, t1); \
	AESKEYGENASSIST $0x10, k, t0;       \
	EXPAND_KEY_128(keys, 5, k, t0, t1); \
	AESKEYGENASSIST $0x20, k, t0;       \
	EXPAND_KEY_128(keys, 6, k, t0, t1); \
	AESKEYGENASSIST $0x40, k, t0;       \
	EXPAND_KEY_128(keys, 7, k, t0, t1); \
	AESKEYGENASSIST $0x80, k, t0;       \
	EXPAND_KEY_128(keys, 8, k, t0, t1); \
	AESKEYGENASSIST $0x1b, k, t0;       \
	EXPAND_KEY_128(keys, 9, k, t0, t1); \
	AESKEYGENASSIST $0x36, k, t0;       \
	EXPAND_KEY_128(keys, 10, k, t0, t1)

#define AES_KEY_SCHEDULE_192(keys, k0, k1, t0, t1, t2, t3, t4) \
	PXOR            t1, t1;                                 \
	MOVUPS          k0, (0 * 16)(keys);                     \
	AESKEYGENASSIST $0x01, k1, t0;                          \
	EXPAND_KEY_192_A(keys, 1, k0, t0, k1, t1, t2, t3, t4);  \
	AESKEYGENASSIST $0x02, k1, t0;                          \
	EXPAND_KEY_192_B(keys, 3, k0, t0, k1, t1, t2, t4);      \
	AESKEYGENASSIST $0x04, k1, t0;                          \
	EXPAND_KEY_192_A(keys, 4, k0, t0, k1, t1, t2, t3, t4);  \
	AESKEYGENASSIST $0x08, k1, t0;                          \
	EXPAND_KEY_192_B(keys, 6, k0, t0, k1, t1, t2, t4);      \
	AESKEYGENASSIST $0x10, k1, t0;                          \
	EXPAND_KEY_192_A(keys, 7, k0, t0, k1, t1, t2, t3, t4);  \
	AESKEYGENASSIST $0x20, k1, t0;                          \
	EXPAND_KEY_192_B(keys, 9, k0, t0, k1, t1, t2, t4);      \
	AESKEYGENASSIST $0x40, k1, t0;                          \
	EXPAND_KEY_192_A(keys, 10, k0, t0, k1, t1, t2, t3, t4); \
	AESKEYGENASSIST $0x80, k1, t0;                          \
	EXPAND_KEY_192_B(keys, 12, k0, t0, k1, t1, t2, t4)

#define AES_KEY_SCHEDULE_256(keys, k0, k1, t0, t1) \
	PXOR            t1, t1;               \
	MOVUPS          k0, (0 * 16)(keys);   \
	MOVUPS          k1, (1 * 16)(keys);   \
	AESKEYGENASSIST $0x01, k1, t0;        \
	EXPAND_KEY_128(keys, 2, k0, t0, t1);  \
	AESKEYGENASSIST $0x01, k0, t0;        \
	EXPAND_KEY_256(keys, 3, k1, t0, t1);  \
	AESKEYGENASSIST $0x02, k1, t0;        \
	EXPAND_KEY_128(keys, 4, k0, t0, t1);  \
	AESKEYGENASSIST $0x02, k0, t0;        \
	EXPAND_KEY_256(keys, 5, k1, t0, t1);  \
	AESKEYGENASSIST $0x04, k1, t0;        \
	EXPAND_KEY_128(keys, 6, k0, t0, t1);  \
	AESKEYGENASSIST $0x04, k0, t0;        \
	EXPAND_KEY_256(keys, 7, k1, t0, t1);  \
	AESKEYGENASSIST $0x08, k1, t0;        \
	EXPAND_KEY_128(keys, 8, k0, t0, t1);  \
	AESKEYGENASSIST $0x08, k0, t0;        \
	EXPAND_KEY_256(keys, 9, k1, t0, t1);  \
	AESKEYGENASSIST $0x10, k1, t0;        \
	EXPAND_KEY_128(keys, 10, k0, t0, t1); \
	AESKEYGENASSIST $0x10, k0, t0;        \
	EXPAND_KEY_256(keys, 11, k1, t0, t1); \
	AESKEYGENASSIST $0x20, k1, t0;        \
	EXPAND_KEY_128(keys, 12, k0, t0, t1); \
	AESKEYGENASSIST $0x20, k0, t0;        \
	EXPAND_KEY_256(keys, 13, k1, t0, t1); \
	AESKEYGENASSIST $0x40, k1, t0;        \
	EXPAND_KEY_128(keys, 14, k0, t0, t1)
