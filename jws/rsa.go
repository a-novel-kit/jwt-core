package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
)

// SignRSA signs a string using RSA PKCS1 v1.5 and returns the signature.
//
// Deprecated: RSASSA PKCS #1 v1.5 has been deprecated by the standards, and is only included for
// backwards compatibility. Use SignRSAPSS instead.
//
// https://www.rfc-editor.org/rfc/rfc8017#section-8
func SignRSA(unsigned string, key *rsa.PrivateKey, hash crypto.Hash) (string, error) {
	if !hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := hash.New()
	hasher.Write([]byte(unsigned))

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, hash, hasher.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("rsa.SignPKCS1v15: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

// VerifyRSA verifies a signature against a string using RSA PKCS1 v1.5.
//
// Deprecated: RSASSA PKCS #1 v1.5 has been deprecated by the standards, and is only included for
// backwards compatibility. Use VerifyRSAPSS instead.
//
// https://www.rfc-editor.org/rfc/rfc8017#section-8
func VerifyRSA(unsigned string, signature string, key *rsa.PublicKey, hash crypto.Hash) error {
	if !hash.Available() {
		return ErrHashUnavailable
	}

	if signature == "" {
		return nil
	}

	hasher := hash.New()
	hasher.Write([]byte(unsigned))

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}

	err = rsa.VerifyPKCS1v15(key, hash, hasher.Sum(nil), sigBytes)
	if err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return ErrInvalidSignature
		}

		return fmt.Errorf("rsa.VerifyPKCS1v15: %w", err)
	}

	return nil
}
