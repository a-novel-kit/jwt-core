package jwscore

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// SignED25519 signs the payload using the EdDSA algorithm with Ed25519 curve.
func SignED25519(unsigned string, key ed25519.PrivateKey) string {
	signed := ed25519.Sign(key, []byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(signed)
}

// VerifyED25519 verifies the signature of the payload using the EdDSA algorithm with Ed25519 curve.
func VerifyED25519(unsigned string, signature string, key ed25519.PublicKey) error {
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	ok := ed25519.Verify(key, []byte(unsigned), sig)
	if !ok {
		return ErrInvalidSignature
	}

	return nil
}
