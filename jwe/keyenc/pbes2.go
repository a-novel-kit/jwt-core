package keyenc

import (
	"crypto"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

var ErrUnsupportedHash = errors.New("unsupported hash")

// DerivePBES2 derives a Key Wrapping Key (KWK) from a password using PBES2.
func DerivePBES2(hash crypto.Hash, salt, password []byte, iterations int) ([]byte, error) {
	var keylen int
	switch hash {
	case crypto.SHA256:
		keylen = 16
	case crypto.SHA384:
		keylen = 24
	case crypto.SHA512:
		keylen = 32
	default:
		return nil, ErrUnsupportedHash
	}

	return pbkdf2.Key(password, salt, iterations, keylen, hash.New), nil
}
