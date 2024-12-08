package keyagr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
)

// https://stackoverflow.com/a/74259220/9021186

// ComputeECSharedSecret computes the shared secret Z between 2 unrelated ECDSA keys.
//
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
//
// A shared secret Z is computed using the domain parameters (q, FR, a, b{, SEED}, G, n, h), the
// other party’s public key, and one’s own private key. This primitive is used in Section 6 by the
// Full Unified Model, Ephemeral Unified Model, One-Pass Unified Model, One-Pass DiffieHellman and Static Unified
// Model schemes. Assume that the party performing the computation
// is party A, and the other party is party B. Note that party A could be either party U or party V.
//
// Both keys must be on the same curve.
func ComputeECSharedSecret(ownPrivKey *ecdsa.PrivateKey, sharedPubKey *ecdsa.PublicKey) ([]byte, error) {
	if !ownPrivKey.PublicKey.Curve.IsOnCurve(sharedPubKey.X, sharedPubKey.Y) {
		return nil, ErrKeyMismatch
	}

	z, _ := ownPrivKey.Curve.ScalarMult(sharedPubKey.X, sharedPubKey.Y, ownPrivKey.D.Bytes())
	zBytes := z.Bytes()

	// Note that calling z.Bytes() on a big.Int may strip leading zero bytes from
	// the returned byte array. This can lead to a problem where zBytes will be
	// shorter than expected which breaks the key derivation. Therefore, we must pad
	// to the full length of the expected coordinate here before calling the KDF.
	octSize := dSize(ownPrivKey.Curve)
	if len(zBytes) != octSize {
		zBytes = append(bytes.Repeat([]byte{0}, octSize-len(zBytes)), zBytes...)
	}

	return zBytes, nil
}

// dSize returns the size in octets for a coordinate on a elliptic curve.
func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / 8
	if bitLen%8 != 0 {
		size++
	}
	return size
}

// DeriveECDHES implements Derive for ECDH-ES.
func DeriveECDHES(
	ownPrivKey *ecdsa.PrivateKey, sharedPubKey *ecdsa.PublicKey, out Alg, apu, apv []byte,
) ([]byte, error) {
	// This is set to the representation of the shared secret Z as an octet sequence.
	z, err := ComputeECSharedSecret(ownPrivKey, sharedPubKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	return Derive(z, out, apu, apv)
}
