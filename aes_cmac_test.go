// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package siv

import (
	"bytes"
	"testing"

	"golang.org/x/sys/cpu"
)

func TestAESCMAC(t *testing.T) {
	hasAES := cpu.X86.HasAES
	defer func(hasAES bool) { cpu.X86.HasAES = hasAES }(hasAES)

	if hasAES {
		t.Run("Asm", testAESCMAC)
		cpu.X86.HasAES = false
	}
	t.Run("Generic", testAESCMAC)
}

func testAESCMAC(t *testing.T) {
	for i, v := range aesSivTests {
		c, err := NewCMAC(v.Key())
		if err != nil {
			t.Errorf("Test %d: Failed to create AES_SIV: %v", i, err)
			continue
		}
		ciphertext := c.Seal(nil, v.Nonce(), v.Plaintext(), v.AdditionalData())
		if !bytes.Equal(ciphertext, v.Ciphertext()) {
			t.Errorf("Test %d: Seal - ciphertext mismatch", i)
		}
		plaintext, err := c.Open(ciphertext[c.Overhead():c.Overhead()], v.Nonce(), ciphertext, v.AdditionalData())
		if err != nil {
			t.Errorf("Test %d: Open - %v", i, err)
		}
		if !bytes.Equal(plaintext, v.Plaintext()) {
			t.Errorf("Test %d: Open - plaintext mismatch", i)
		}
	}
}

func TestAESCMACAssembler(t *testing.T) {
	if !cpu.X86.HasAES {
		t.Skip("No assembler implementation / AES hardware support")
	}
	keys := [][]byte{make([]byte, 32), make([]byte, 48), make([]byte, 64)}
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte(i*j + len(keys))
		}
	}
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	plaintext := make([]byte, 1024)
	ciphertext := make([]byte, len(plaintext)+16)
	for i := range keys {
		for j := range plaintext {
			plaintext[i] = byte(j + i)
			testAESCMACAssmebler(i, ciphertext[:16+j], nonce, plaintext[:j], plaintext[j:], keys[i], t)
		}
	}
}

func testAESCMACAssmebler(i int, ciphertext, nonce, plaintext, additionalData, key []byte, t *testing.T) {
	hasAES := cpu.X86.HasAES
	defer func(hasAES bool) { cpu.X86.HasAES = hasAES }(hasAES)

	c, err := NewCMAC(key)
	if err != nil {
		t.Fatalf("Test %d: failed to create AES-SIV-CMAC: %v", i, err)
	}
	ciphertext = c.Seal(ciphertext[:0], nonce, plaintext, additionalData)
	asmPlaintext, err := c.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Test %d: Open failed: %v", i, err)
	}
	if !bytes.Equal(plaintext, asmPlaintext) {
		t.Fatalf("Test %d: plaintext mismatch", i)
	}

	cpu.X86.HasAES = false // Disable AES assembler implementations

	c, err = NewCMAC(key)
	if err != nil {
		t.Fatalf("Test %d: failed to create AES-SIV-CMAC: %v", i, err)
	}
	refCiphertext := c.Seal(nil, nonce, plaintext, additionalData)
	if !bytes.Equal(refCiphertext, ciphertext) {
		t.Fatalf("Test %d: ciphertext mismatch", i)
	}
	refPlaintext, err := c.Open(ciphertext[16:16], nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Test %d: Open failed: %v", i, err)
	}
	if !bytes.Equal(plaintext, refPlaintext) {
		t.Fatalf("Test %d: plaintext mismatch", i)
	}
}

func BenchmarkAES128CMACSeal64(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 32), 64, b) }
func BenchmarkAES128CMACSeal1K(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 32), 1024, b) }
func BenchmarkAES128CMACSeal8K(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 32), 8*1024, b) }
func BenchmarkAES128CMACOpen64(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 32), 64, b) }
func BenchmarkAES128CMACOpen1K(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 32), 1024, b) }
func BenchmarkAES128CMACOpen8K(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 32), 8*1024, b) }

func BenchmarkAES192CMACSeal64(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 48), 64, b) }
func BenchmarkAES192CMACSeal1K(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 48), 1024, b) }
func BenchmarkAES192CMACSeal8K(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 48), 8*1024, b) }
func BenchmarkAES192CMACOpen64(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 48), 64, b) }
func BenchmarkAES192CMACOpen1K(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 48), 1024, b) }
func BenchmarkAES192CMACOpen8K(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 48), 8*1024, b) }

func BenchmarkAES256CMACSeal64(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 64), 64, b) }
func BenchmarkAES256CMACSeal1K(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 64), 1024, b) }
func BenchmarkAES256CMACSeal8K(b *testing.B) { benchmarkAESCMACSeal(make([]byte, 64), 8*1024, b) }
func BenchmarkAES256CMACOpen64(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 64), 64, b) }
func BenchmarkAES256CMACOpen1K(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 64), 1024, b) }
func BenchmarkAES256CMACOpen8K(b *testing.B) { benchmarkAESCMACOpen(make([]byte, 64), 8*1024, b) }

func benchmarkAESCMACSeal(key []byte, size int64, b *testing.B) {
	c, err := NewCMAC(key)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, size)
	ciphertext := make([]byte, len(plaintext)+16)

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		c.Seal(ciphertext[:0], nil, plaintext, nil)
	}
}

func benchmarkAESCMACOpen(key []byte, size int64, b *testing.B) {
	c, err := NewCMAC(key)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, size)
	ciphertext := c.Seal(nil, nil, plaintext, nil)

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		if _, err := c.Open(plaintext[:0], nil, ciphertext, nil); err != nil {
			panic(err)
		}
	}
}
