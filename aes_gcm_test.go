// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.
package siv

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/sys/cpu"
)

func TestAESGCM(t *testing.T) {
	hasAES, hashGHASH := cpu.X86.HasAES, cpu.X86.HasPCLMULQDQ
	defer func(hasAES, hashGHASH bool) { cpu.X86.HasAES, cpu.X86.HasPCLMULQDQ = hasAES, hashGHASH }(hasAES, hashGHASH)

	if hasAES && hashGHASH {
		t.Run("Asm", testAESGCM)
		cpu.X86.HasAES, cpu.X86.HasPCLMULQDQ = false, false
	}
	t.Run("Generic", testAESGCM)
}

func testAESGCM(t *testing.T) {
	for i, v := range aesGcmSivTests {
		c, err := NewGCM(v.Key())
		if err != nil {
			t.Errorf("Test %d: Failed to create AES_SIV: %v", i, err)
			continue
		}
		ciphertext := c.Seal(nil, v.Nonce(), v.Plaintext(), v.AdditionalData())
		if !bytes.Equal(ciphertext, v.Ciphertext()) {
			t.Errorf("Test %d: Seal - ciphertext mismatch: %s - %s", i, v.ciphertext, hex.EncodeToString(ciphertext))
		}
		plaintext, err := c.Open(ciphertext[:0], v.Nonce(), ciphertext, v.AdditionalData())
		if err != nil {
			t.Errorf("Test %d: Open failed - %v", i, err)
		}
		if !bytes.Equal(plaintext, v.Plaintext()) {
			t.Errorf("Test %d: Open - plaintext mismatch", i)
		}
	}
}

func TestAESGCMAssembler(t *testing.T) {
	if !cpu.X86.HasAES || !cpu.X86.HasPCLMULQDQ {
		t.Skip("No assembler implementation / AES hardware support")
	}
	keys := [][]byte{make([]byte, 16), make([]byte, 32)}
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte(i*j + len(keys))
		}
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	plaintext := make([]byte, 1024)
	ciphertext := make([]byte, len(plaintext)+16)
	for i := range keys {
		for j := range plaintext {
			plaintext[i] = byte(j + i)
			testAESGCMAssmebler(i, ciphertext[:16+j], nonce, plaintext[:j], plaintext[j:], keys[i], t)
		}
	}
}

func testAESGCMAssmebler(i int, ciphertext, nonce, plaintext, additionalData, key []byte, t *testing.T) {
	hasAES, hashGHASH := cpu.X86.HasAES, cpu.X86.HasPCLMULQDQ
	defer func(hasAES, hashGHASH bool) { cpu.X86.HasAES, cpu.X86.HasPCLMULQDQ = hasAES, hashGHASH }(hasAES, hashGHASH)

	c, err := NewGCM(key)
	if err != nil {
		t.Fatalf("Test %d: failed to create AES-GCM-SIV: %v", i, err)
	}
	ciphertext = c.Seal(ciphertext[:0], nonce, plaintext, additionalData)
	asmPlaintext, err := c.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Test %d: Open failed: %v", i, err)
	}
	if !bytes.Equal(plaintext, asmPlaintext) {
		t.Fatalf("Test %d: plaintext mismatch", i)
	}

	cpu.X86.HasAES, cpu.X86.HasPCLMULQDQ = false, false // Disable AES assembler implementations

	c, err = NewGCM(key)
	if err != nil {
		t.Fatalf("Test %d: failed to create AES-GCM-SIV: %v", i, err)
	}
	refCiphertext := c.Seal(nil, nonce, plaintext, additionalData)
	if !bytes.Equal(refCiphertext, ciphertext) {
		t.Fatalf("Test %d: ciphertext mismatch", i)
	}
	refPlaintext, err := c.Open(ciphertext[:0], nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Test %d: Open failed: %v", i, err)
	}
	if !bytes.Equal(plaintext, refPlaintext) {
		t.Fatalf("Test %d: plaintext mismatch", i)
	}
}

func BenchmarkAES128GCMSeal64(b *testing.B) { benchmarkAESGCMSeal(make([]byte, 16), 64, b) }
func BenchmarkAES128GCMSeal1K(b *testing.B) { benchmarkAESGCMSeal(make([]byte, 16), 1024, b) }
func BenchmarkAES128GCMSeal8K(b *testing.B) { benchmarkAESGCMSeal(make([]byte, 16), 8*1024, b) }
func BenchmarkAES128GCMOpen64(b *testing.B) { benchmarkAESGCMOpen(make([]byte, 16), 64, b) }
func BenchmarkAES128GCMOpen1K(b *testing.B) { benchmarkAESGCMOpen(make([]byte, 16), 1024, b) }
func BenchmarkAES128GCMOpen8K(b *testing.B) { benchmarkAESGCMOpen(make([]byte, 16), 8*1024, b) }
func BenchmarkAES256GCMSeal64(b *testing.B) { benchmarkAESGCMSeal(make([]byte, 32), 64, b) }
func BenchmarkAES256GCMSeal1K(b *testing.B) { benchmarkAESGCMSeal(make([]byte, 32), 1024, b) }
func BenchmarkAES256GCMSeal8K(b *testing.B) { benchmarkAESGCMSeal(make([]byte, 32), 8*1024, b) }
func BenchmarkAES256GCMOpen64(b *testing.B) { benchmarkAESGCMOpen(make([]byte, 32), 64, b) }
func BenchmarkAES256GCMOpen1K(b *testing.B) { benchmarkAESGCMOpen(make([]byte, 32), 1024, b) }
func BenchmarkAES256GCMOpen8K(b *testing.B) { benchmarkAESGCMOpen(make([]byte, 32), 8*1024, b) }

func benchmarkAESGCMSeal(key []byte, size int64, b *testing.B) {
	c, err := NewGCM(key)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, c.NonceSize())
	plaintext := make([]byte, size)
	ciphertext := make([]byte, len(plaintext)+16)

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		c.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

func benchmarkAESGCMOpen(key []byte, size int64, b *testing.B) {
	c, err := NewGCM(key)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, c.NonceSize())
	plaintext := make([]byte, size)
	ciphertext := c.Seal(nil, nonce, plaintext, nil)

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		if _, err := c.Open(plaintext[:0], nonce, ciphertext, nil); err != nil {
			panic(err)
		}
	}
}
