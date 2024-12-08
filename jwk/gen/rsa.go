package jwkgen

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

const (
	// RS256KeySize is the recommended key size for RSA 256 keys.
	//
	// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
	// to the next integer.
	//
	// ⌈2048/8⌉=256 bytes.
	//
	// https://crypto.stackexchange.com/a/95882
	RS256KeySize = 2048
	// RS384KeySize is the recommended key size for RSA 384 keys.
	//
	// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
	// to the next integer.
	//
	// ⌈3072/8⌉=384 bytes.
	//
	// https://crypto.stackexchange.com/a/95882
	RS384KeySize = 3072
	// RS512KeySize is the recommended key size for RSA 512 keys.
	//
	// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
	// to the next integer.
	//
	// ⌈4096/8⌉=512 bytes.
	//
	// https://crypto.stackexchange.com/a/95882
	RS512KeySize = 4096
)

// RSA generates a new RSA private key of the given size.
// The generated key can be used to sign a token using RSA.
//
// You can use the recommended default constants as the size parameter.
//   - RS256KeySize
//   - RS384KeySize
//   - RS512KeySize
func RSA(size int) (*rsa.PrivateKey, error) {
	// Private CEK generation
	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	// Validate Private CEK
	err = privateKey.Validate()
	if err != nil {
		return nil, fmt.Errorf("validate rsa key: %w", err)
	}

	privateKey.Precompute()

	return privateKey, nil
}
