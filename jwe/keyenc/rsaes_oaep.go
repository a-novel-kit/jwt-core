package keyenc

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
)

// EncryptRSAESOAEP encrypts the CEK using RSAES-OAEP algorithm.
func EncryptRSAESOAEP(key *rsa.PublicKey, keyHash hash.Hash, cek []byte) ([]byte, error) {
	encoded, err := rsa.EncryptOAEP(keyHash, rand.Reader, key, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt RSAES-OAEP: %w", err)
	}

	return encoded, nil
}

// DecryptRSAESOAEP decrypts the CEK using RSAES-OAEP algorithm.
func DecryptRSAESOAEP(key *rsa.PrivateKey, keyHash hash.Hash, encrypted []byte) ([]byte, error) {
	decoded, err := rsa.DecryptOAEP(keyHash, rand.Reader, key, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt RSAES-OAEP: %w", err)
	}

	return decoded, nil
}
