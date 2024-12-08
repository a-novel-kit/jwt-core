package jwkgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

// EC generates a new ECDSA private key of the given curve.
//
// The curve must be one of the following:
// - elliptic.P256()
// - elliptic.P384()
// - elliptic.P521()
func EC(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa256 key: %w", err)
	}

	return privateKey, nil
}
