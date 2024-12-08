package keyagr

import (
	"crypto/ecdh"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// ComputeSharedEDSecret computes the shared secret between two Ed25519 keys.
//
// https://datatracker.ietf.org/doc/html/rfc8037#section-3.2.1
//
// Apply the appropriate ECDH function to the ephemeral private key (as
// scalar input) and receiver public key (as u-coordinate input). The
// output is the Z value.
func ComputeSharedEDSecret(ownPrivKey *ecdh.PrivateKey, sharedPubKey *ecdh.PublicKey) ([]byte, error) {
	z, err := curve25519.X25519(ownPrivKey.Bytes(), sharedPubKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	return z, nil
}

// DeriveECDHED implements Derive for ECDH-ED.
func DeriveECDHED(
	ownPrivKey *ecdh.PrivateKey, sharedPubKey *ecdh.PublicKey, out Alg, apu, apv []byte,
) ([]byte, error) {
	// This is set to the representation of the shared secret Z as an octet sequence.
	z, err := ComputeSharedEDSecret(ownPrivKey, sharedPubKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	return Derive(z, out, apu, apv)
}
