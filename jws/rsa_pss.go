package jwscore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
)

// SignRSAPSS signs the payload using the RSA-PSS algorithm.
func SignRSAPSS(unsigned string, key *rsa.PrivateKey, hash crypto.Hash) (string, error) {
	if !hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := hash.New()
	hasher.Write([]byte(unsigned))

	sigBytes, err := rsa.SignPSS(rand.Reader, key, hash, hasher.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		return "", fmt.Errorf("rsa.SignPSS: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

// VerifyRSAPSS verifies the signature of the payload using the RSA-PSS algorithm.
func VerifyRSAPSS(unsigned string, signature string, key *rsa.PublicKey, hash crypto.Hash) error {
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

	err = rsa.VerifyPSS(key, hash, hasher.Sum(nil), sigBytes, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return ErrInvalidSignature
		}

		return fmt.Errorf("rsa.VerifyPSS: %w", err)
	}

	return nil
}
