package jwx509

import (
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
)

var (
	ErrCertMismatch    = errors.New("certificate chains are not semantically equal")
	ErrCertKeyMismatch = errors.New("public keys in key and x5c fields do not match")
)

// Match checks if two certificate chains are semantically equal.
func Match(chain1, chain2 []*x509.Certificate) error {
	if len(chain1) != len(chain2) {
		return ErrCertMismatch
	}

	for pos := range chain1 {
		if !chain1[pos].Equal(chain2[pos]) {
			return ErrCertMismatch
		}
	}

	return nil
}

// MatchKey checks if the public key embedded in the JWK matches the public key embedded in the certificate.
func MatchKey(keyPub interface{}, certs []*x509.Certificate) error {
	if len(certs) == 0 || keyPub == nil {
		return nil
	}

	// We need to check that leaf public key matches the key embedded in this
	// JWK, as required by the standard (see RFC 7517, Section 4.7). Otherwise
	// the JWK parsed could be semantically invalid. Technically, should also
	// check key usage fields and other extensions on the cert here, but the
	// standard doesn't exactly explain how they're supposed to map from the
	// JWK representation to the X.509 extensions.
	certPub := certs[0].PublicKey

	if !reflect.DeepEqual(certPub, keyPub) {
		return fmt.Errorf("%w:\n\tgot %[2]s (%[2]T)\n\twanted %[3]s (%[3]T)", ErrCertKeyMismatch, certPub, keyPub)
	}

	return nil
}
