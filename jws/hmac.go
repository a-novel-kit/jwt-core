package jwscore

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
)

// SignHMAC signs the unsigned string using the HMAC algorithm.
func SignHMAC(unsigned string, key []byte, hash crypto.Hash) (string, error) {
	if !hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := hmac.New(hash.New, key)
	hasher.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyHMAC verifies the signature of the unsigned string using the HMAC algorithm.
func VerifyHMAC(unsigned string, signature string, key []byte, hash crypto.Hash) error {
	if !hash.Available() {
		return ErrHashUnavailable
	}

	if signature == "" {
		return nil
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hasher := hmac.New(hash.New, key)
	hasher.Write([]byte(unsigned))

	if !hmac.Equal(sigBytes, hasher.Sum(nil)) {
		return ErrInvalidSignature
	}

	return nil
}
