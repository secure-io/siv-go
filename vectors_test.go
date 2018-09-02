package siv

import "encoding/hex"

func mustDecode(s string) []byte {
	v, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return v
}

type vector struct{ key, plaintext, additionalData, nonce, ciphertext string }

func (v vector) Key() []byte            { return mustDecode(v.key) }
func (v vector) Plaintext() []byte      { return mustDecode(v.plaintext) }
func (v vector) AdditionalData() []byte { return mustDecode(v.additionalData) }
func (v vector) Nonce() []byte          { return mustDecode(v.nonce) }
func (v vector) Ciphertext() []byte     { return mustDecode(v.ciphertext) }

var aesSivTests = []vector{
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		plaintext:      "112233445566778899aabbccddee",
		additionalData: "101112131415161718191a1b1c1d1e1f2021222324252627",
		nonce:          "",
		ciphertext:     "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c",
	},
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f",
		plaintext:      "112233445566778899aabbccddee",
		additionalData: "101112131415161718191a1b1c1d1e1f2021222324252627",
		nonce:          "",
		ciphertext:     "f125274c598065cfc26b0e71575029088b035217e380cac8919ee800c126",
	},
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		plaintext:      "",
		additionalData: "",
		nonce:          "",
		ciphertext:     "f2007a5beb2b8900c588a7adf599f172",
	},
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		plaintext:      "00112233445566778899aabbccddeeff",
		additionalData: "",
		nonce:          "",
		ciphertext:     "f304f912863e303d5b540e5057c7010c942ffaf45b0e5ca5fb9a56a5263bb065",
	},
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		plaintext:      "112233445566778899aabbccddee",
		additionalData: "",
		nonce:          "101112131415161718191a1b1c1d1e1f2021222324252627",
		ciphertext:     "4b3d0f15ae9ffa9e65b949421582ef70e410910d6446c7759ebff9b5385a",
	},
	{
		key:            "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
		plaintext:      "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
		additionalData: "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
		nonce:          "09f911029d74e35bd84156c5635688c0",
		ciphertext:     "85825e22e90cf2ddda2c548dc7c1b6310dcdaca0cebf9dc6cb90583f5bf1506e02cd48832b00e4e598b2b22a53e6199d4df0c1666a35a0433b250dc134d776",
	},
	{
		key:            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f",
		plaintext:      "112233445566778899aabbccddee",
		additionalData: "",
		nonce:          "101112131415161718191a1b1c1d1e1f2021222324252627",
		ciphertext:     "e618d2d6a86b50a8d7df82ab34aa950ab319d7fc15f7cd1ea99b1a033f20",
	},
}
