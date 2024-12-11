package jwscore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

var ErrUnsupportedCurve = errors.New("unsupported curve")

func inferECDSAKeySize(params *elliptic.CurveParams) int {
	curveBits := params.BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	return keyBytes
}

// SignEC signs the payload using the Elliptic Curve algorithm.
func SignEC(unsigned string, key *ecdsa.PrivateKey) (string, error) {
	var hash crypto.Hash
	switch key.Curve.Params().Name {
	case "P-256":
		hash = crypto.SHA256
	case "P-384":
		hash = crypto.SHA384
	case "P-521":
		hash = crypto.SHA512
	default:
		return "", ErrUnsupportedCurve
	}

	hasher := hash.New()
	hasher.Write([]byte(unsigned))

	r, s, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil)) //nolint:varnamelen
	if err != nil {
		return "", fmt.Errorf("sign payload: %w", err)
	}

	keyBytes := inferECDSAKeySize(key.Curve.Params())

	// We serialize the outputs (r and s) into big-endian byte arrays
	// padded with zeros on the left to make sure the sizes work out.
	// Output must be 2*keyBytes long.
	out := make([]byte, 2*keyBytes)
	r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
	s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// VerifyEC verifies the signature of the payload using the Elliptic Curve algorithm.
func VerifyEC(unsigned string, signature string, key *ecdsa.PublicKey) error {
	var hash crypto.Hash
	switch key.Curve.Params().Name {
	case "P-256":
		hash = crypto.SHA256
	case "P-384":
		hash = crypto.SHA384
	case "P-521":
		hash = crypto.SHA512
	default:
		return ErrUnsupportedCurve
	}

	if signature == "" {
		return nil
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	keyBytes := inferECDSAKeySize(key.Curve.Params())
	if len(sigBytes) != 2*keyBytes {
		return nil
	}

	r := big.NewInt(0).SetBytes(sigBytes[:keyBytes]) //nolint:varnamelen
	s := big.NewInt(0).SetBytes(sigBytes[keyBytes:])

	hasher := hash.New()
	hasher.Write([]byte(unsigned))

	if !ecdsa.Verify(key, hasher.Sum(nil), r, s) {
		return ErrInvalidSignature
	}

	return nil
}
