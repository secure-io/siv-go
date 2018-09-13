package siv_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	siv "github.com/secure-io/siv-go"
)

func ExampleNewCMAC_encrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like argon2 (`go doc golang.org/x/crypto/argon2`).
	// When decoded the key should be 32 bytes (AES-128) or 64 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("example_plaintext")

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		panic(err.Error())
	}

	// An empty nonce makes AES-SIV-CMAC a deterministic authenticated encryption
	// scheme (same plaintext && additional data produces the same ciphertext).
	// You can also use a random 16 byte nonce to make AES-SIV-CMAC non-deterministic.
	var nonce []byte = nil

	ciphertext := aessiv.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%x\n", ciphertext)
	// Output: 485bdd0e072f857e623620ebad3eb1925bcb1cafc1780d625710b6bcdd34bf79b2
}

func ExampleNewCMAC_decrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like argon2 (`go doc golang.org/x/crypto/argon2`).
	// When decoded the key should be 32 bytes (AES-128) or 64 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString("485bdd0e072f857e623620ebad3eb1925bcb1cafc1780d625710b6bcdd34bf79b2")
	var nonce []byte = nil // An empty nonce was used to encrypt the plaintext.

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aessiv.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%s\n", plaintext)
	// Output: example_plaintext
}

func ExampleNewCMAC_encryptDecrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like argon2 (`go doc golang.org/x/crypto/argon2`).
	// When decoded the key should be 32 bytes (AES-128) or 64 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("example_plaintext")

	aessiv, err := siv.NewCMAC(key)
	if err != nil {
		panic(err.Error())
	}

	// We use a random nonce to make AES-SIV-CMAC a probabilistic authenticated
	// encryption scheme.
	nonce := make([]byte, aessiv.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := aessiv.Seal(nil, nonce, plaintext, nil)
	plaintext, err = aessiv.Open(plaintext[:0], nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%s\n", plaintext)
	// Output: example_plaintext
}

func ExampleNewGCM_encrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like argon2 (`go doc golang.org/x/crypto/argon2`).
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("example_plaintext")

	aessiv, err := siv.NewGCM(key)
	if err != nil {
		panic(err.Error())
	}

	// A fixed nonce makes AES-GCM-SIV a deterministic authenticated encryption
	// scheme (same plaintext && additional data produces the same ciphertext).
	// You can also use a random 12 byte nonce to make AES-GCM-SIV non-deterministic.
	nonce := make([]byte, aessiv.NonceSize())

	ciphertext := aessiv.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%x\n", ciphertext)
	// Output: eb87399f2550f35b572b10b1a269b6446dce046bfd35e48208b7efa7a7b934cf69
}

func ExampleNewGCM_decrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like argon2 (`go doc golang.org/x/crypto/argon2`).
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString("eb87399f2550f35b572b10b1a269b6446dce046bfd35e48208b7efa7a7b934cf69")

	aessiv, err := siv.NewGCM(key)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aessiv.NonceSize()) // An fixed nonce was used to encrypt the plaintext.

	plaintext, err := aessiv.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%s\n", plaintext)
	// Output: example_plaintext
}

func ExampleNewGCM_encryptDecrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like argon2 (`go doc golang.org/x/crypto/argon2`).
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("example_plaintext")

	aessiv, err := siv.NewGCM(key)
	if err != nil {
		panic(err.Error())
	}

	// We use a random nonce to make AES-GCM-SIV a probabilistic authenticated
	// encryption scheme.
	nonce := make([]byte, aessiv.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := aessiv.Seal(nil, nonce, plaintext, nil)
	plaintext, err = aessiv.Open(plaintext[:0], nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%s\n", plaintext)
	// Output: example_plaintext
}
