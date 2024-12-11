package jwkgen

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// ED25519 generates a new EdDSA key pair.
func ED25519() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ED25519 key pair : %w", err)
	}

	return privateKey, publicKey, nil
}
