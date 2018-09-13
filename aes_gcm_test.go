// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.
package siv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESGCM(t *testing.T) {
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
