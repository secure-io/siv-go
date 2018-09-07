// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package siv

import (
	"bytes"
	"testing"
)

func TestAESCMAC(t *testing.T) {
	for i, v := range aesSivTests {
		c, err := NewCMAC(v.Key())
		if err != nil {
			t.Errorf("Test %d: Failed to create AES_SIV: %v", i, err)
			continue
		}
		ciphertext := c.Seal(nil, v.Plaintext(), v.Nonce(), v.AdditionalData())
		if !bytes.Equal(ciphertext, v.Ciphertext()) {
			t.Errorf("Test %d: Seal - ciphertext mismatch", i)
		}
		plaintext, err := c.Open(ciphertext[c.Overhead():c.Overhead()], ciphertext, v.Nonce(), v.AdditionalData())
		if err != nil {
			t.Errorf("Test %d: Open - %v", i, err)
		}
		if !bytes.Equal(plaintext, v.Plaintext()) {
			t.Errorf("Test %d: Open - plaintext mismatch", i)
		}
	}
}

func BenchmarkAES128CMACSeal64(b *testing.B) { benchmarkSeal(make([]byte, 32), 64, b) }
func BenchmarkAES128CMACSeal1K(b *testing.B) { benchmarkSeal(make([]byte, 32), 1024, b) }
func BenchmarkAES128CMACSeal8K(b *testing.B) { benchmarkSeal(make([]byte, 32), 8*1024, b) }
func BenchmarkAES128CMACOpen64(b *testing.B) { benchmarkOpen(make([]byte, 32), 64, b) }
func BenchmarkAES128CMACOpen1K(b *testing.B) { benchmarkOpen(make([]byte, 32), 1024, b) }
func BenchmarkAES128CMACOpen8K(b *testing.B) { benchmarkOpen(make([]byte, 32), 8*1024, b) }

func BenchmarkAES192CMACSeal64(b *testing.B) { benchmarkSeal(make([]byte, 48), 64, b) }
func BenchmarkAES192CMACSeal1K(b *testing.B) { benchmarkSeal(make([]byte, 48), 1024, b) }
func BenchmarkAES192CMACSeal8K(b *testing.B) { benchmarkSeal(make([]byte, 48), 8*1024, b) }
func BenchmarkAES192CMACOpen64(b *testing.B) { benchmarkOpen(make([]byte, 48), 64, b) }
func BenchmarkAES192CMACOpen1K(b *testing.B) { benchmarkOpen(make([]byte, 48), 1024, b) }
func BenchmarkAES192CMACOpen8K(b *testing.B) { benchmarkOpen(make([]byte, 48), 8*1024, b) }

func BenchmarkAES256CMACSeal64(b *testing.B) { benchmarkSeal(make([]byte, 64), 64, b) }
func BenchmarkAES256CMACSeal1K(b *testing.B) { benchmarkSeal(make([]byte, 64), 1024, b) }
func BenchmarkAES256CMACSeal8K(b *testing.B) { benchmarkSeal(make([]byte, 64), 8*1024, b) }
func BenchmarkAES256CMACOpen64(b *testing.B) { benchmarkOpen(make([]byte, 64), 64, b) }
func BenchmarkAES256CMACOpen1K(b *testing.B) { benchmarkOpen(make([]byte, 64), 1024, b) }
func BenchmarkAES256CMACOpen8K(b *testing.B) { benchmarkOpen(make([]byte, 64), 8*1024, b) }

func benchmarkSeal(key []byte, size int64, b *testing.B) {
	c, err := NewCMAC(key)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, size)
	ciphertext := make([]byte, len(plaintext)+16)

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		c.Seal(ciphertext[:0], plaintext, nil, nil)
	}
}

func benchmarkOpen(key []byte, size int64, b *testing.B) {
	c, err := NewCMAC(key)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, size)
	ciphertext := c.Seal(nil, plaintext, nil, nil)

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		if _, err := c.Open(plaintext[:0], ciphertext, nil, nil); err != nil {
			panic(err)
		}
	}
}
