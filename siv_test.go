package siv

import (
	"bytes"
	"testing"
)

func TestVectors(t *testing.T) {
	for i, v := range aesSivTests {
		c, err := NewAESWithNonceSize(v.Key(), len(v.Nonce()))
		if err != nil {
			t.Errorf("Test %d: Failed to create AES_SIV: %v", i, err)
			continue
		}
		ciphertext := c.Seal(nil, v.Plaintext(), v.Nonce(), v.AdditionalData())
		if !bytes.Equal(ciphertext, v.Ciphertext()) {
			t.Errorf("Test %d: Seal - ciphertext mismatch", i)
		}
		plaintext, err := c.Open(nil, ciphertext, v.Nonce(), v.AdditionalData())
		if err != nil {
			t.Errorf("Test %d: Open - %v", i, err)
		}
		if !bytes.Equal(plaintext, v.Plaintext()) {
			t.Errorf("Test %d: Open - plaintext mismatch", i)
		}
	}
}

func BenchmarkAES128Seal64(b *testing.B) { benchmarkSeal(make([]byte, 32), 64, b) }
func BenchmarkAES128Seal1K(b *testing.B) { benchmarkSeal(make([]byte, 32), 1024, b) }
func BenchmarkAES128Seal8K(b *testing.B) { benchmarkSeal(make([]byte, 32), 8*1024, b) }
func BenchmarkAES128Open64(b *testing.B) { benchmarkOpen(make([]byte, 32), 64, b) }
func BenchmarkAES128Open1K(b *testing.B) { benchmarkOpen(make([]byte, 32), 1024, b) }
func BenchmarkAES128Open8K(b *testing.B) { benchmarkOpen(make([]byte, 32), 8*1024, b) }

func BenchmarkAES192Seal64(b *testing.B) { benchmarkSeal(make([]byte, 48), 64, b) }
func BenchmarkAES192Seal1K(b *testing.B) { benchmarkSeal(make([]byte, 48), 1024, b) }
func BenchmarkAES192Seal8K(b *testing.B) { benchmarkSeal(make([]byte, 48), 8*1024, b) }
func BenchmarkAES192Open64(b *testing.B) { benchmarkOpen(make([]byte, 48), 64, b) }
func BenchmarkAES192Open1K(b *testing.B) { benchmarkOpen(make([]byte, 48), 1024, b) }
func BenchmarkAES192Open8K(b *testing.B) { benchmarkOpen(make([]byte, 48), 8*1024, b) }

func BenchmarkAES256Seal64(b *testing.B) { benchmarkSeal(make([]byte, 64), 64, b) }
func BenchmarkAES256Seal1K(b *testing.B) { benchmarkSeal(make([]byte, 64), 1024, b) }
func BenchmarkAES256Seal8K(b *testing.B) { benchmarkSeal(make([]byte, 64), 8*1024, b) }
func BenchmarkAES256Open64(b *testing.B) { benchmarkOpen(make([]byte, 64), 64, b) }
func BenchmarkAES256Open1K(b *testing.B) { benchmarkOpen(make([]byte, 64), 1024, b) }
func BenchmarkAES256Open8K(b *testing.B) { benchmarkOpen(make([]byte, 64), 8*1024, b) }

func benchmarkSeal(key []byte, size int64, b *testing.B) {
	c, err := NewAES(key)
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
	c, err := NewAES(key)
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
