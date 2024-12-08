package jwkgen

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// X25519 generates a new X25519 key pair.
func X25519() (*ecdh.PrivateKey, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 key pair : %w", err)
	}

	return privateKey, nil
}
