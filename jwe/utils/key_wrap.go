package jweutils

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Shamelessly stolen
// https://github.com/go-jose/go-jose/blob/fdc2ceb0bbe2a29c582edfe07ea914c8dacd7e1b/cipher/key_wrap.go

var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// KeyWrap implements NIST key wrapping; it wraps a content encryption key (cek) with the given block cipher.
func KeyWrap(block cipher.Block, cek []byte) ([]byte, error) {
	if len(cek)%8 != 0 {
		return nil, errors.New("key wrap input must be 8 byte blocks")
	}

	n := len(cek) / 8
	r := make([][]byte, n)

	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], cek[i*8:])
	}

	buffer := make([]byte, 16)
	tBytes := make([]byte, 8)
	copy(buffer, defaultIV)

	for t := range 6 * n {
		copy(buffer[8:], r[t%n])

		block.Encrypt(buffer, buffer)

		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := range 8 {
			buffer[i] ^= tBytes[i]
		}
		copy(r[t%n], buffer[8:])
	}

	out := make([]byte, (n+1)*8)
	copy(out, buffer[:8])
	for i := range r {
		copy(out[(i+1)*8:], r[i])
	}

	return out, nil
}

// KeyUnwrap implements NIST key unwrapping; it unwraps a content encryption key (cek) with the given block cipher.
func KeyUnwrap(block cipher.Block, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 {
		return nil, errors.New("key wrap input must be 8 byte blocks")
	}

	n := (len(ciphertext) / 8) - 1
	r := make([][]byte, n)

	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:])
	}

	buffer := make([]byte, 16)
	tBytes := make([]byte, 8)
	copy(buffer[:8], ciphertext[:8])

	for t := 6*n - 1; t >= 0; t-- {
		binary.BigEndian.PutUint64(tBytes, uint64(t+1))

		for i := range 8 {
			buffer[i] ^= tBytes[i]
		}
		copy(buffer[8:], r[t%n])

		block.Decrypt(buffer, buffer)

		copy(r[t%n], buffer[8:])
	}

	if subtle.ConstantTimeCompare(buffer[:8], defaultIV) == 0 {
		return nil, errors.New("failed to unwrap key")
	}

	out := make([]byte, n*8)
	for i := range r {
		copy(out[i*8:], r[i])
	}

	return out, nil
}
