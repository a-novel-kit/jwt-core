package jwx509

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrNoCerts            = errors.New("no certificates provided")
	ErrThumbprintMismatch = errors.New("thumbprint mismatch")
)

// MatchThumbprint checks if the thumbprint of the first certificate in the chain matches the provided thumbprint.
//
// The thumbprint must be either 20 bytes long (for sha1) or 32 bytes long (for sha256).
func MatchThumbprint(certs []*x509.Certificate, thumbprint []byte) error {
	var actualThumbprint []byte

	if len(certs) == 0 {
		return ErrNoCerts
	}

	switch len(thumbprint) {
	case sha1.Size:
		keyThumbprint := sha1.Sum(certs[0].Raw)
		actualThumbprint = keyThumbprint[:]
	case sha256.Size:
		keyThumbprint := sha256.Sum256(certs[0].Raw)
		actualThumbprint = keyThumbprint[:]
	default:
		return fmt.Errorf(
			"unsupported thumbprint size: %d: must be %d (for sha1) or %d (for sha256) bytes long",
			len(thumbprint), sha1.Size, sha256.Size,
		)
	}

	if !bytes.Equal(thumbprint, actualThumbprint) {
		return fmt.Errorf("%w: expected %x, got %x", ErrThumbprintMismatch, thumbprint, actualThumbprint)
	}

	return nil
}
