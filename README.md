[![Godoc Reference](https://godoc.org/github.com/secure-io/siv?status.svg)](https://godoc.org/github.com/secure-io/siv)

**Warning - This package is just an experimental proof-of-concept implementation.**
**This implementation is currently not optimized for performance or (side channel) security.**

## SIV

Synthetic Initialization Vector (SIV) is an nonce-misuse resistant authenticated
encryption scheme specified in [RFC 5297](https://tools.ietf.org/html/rfc5297) using
AES and CMAC.