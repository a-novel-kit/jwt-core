package keyenc

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// EncryptRSAESPKCS1V15 encrypts the CEK using RSAES-PKCS1-v1.5 algorithm.
//
// Deprecated: RSASSA PKCS #1 v1.5 has been deprecated by the standards, and is only included for
// backwards compatibility. Use EncryptRSAESOAEP instead.
//
// https://www.rfc-editor.org/rfc/rfc8017#section-8
func EncryptRSAESPKCS1V15(key *rsa.PublicKey, cek []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, key, cek)
	if err != nil {
		return nil, fmt.Errorf("encrypt RSAES-PKCS1-v1.5: %w", err)
	}

	return encrypted, nil
}

// DecryptRSAESPKCS1V15 decrypts the CEK using RSAES-PKCS1-v1.5 algorithm.
//
// Deprecated: RSASSA PKCS #1 v1.5 has been deprecated by the standards, and is only included for
// backwards compatibility. Use DecryptRSAESOAEP instead.
//
// https://www.rfc-editor.org/rfc/rfc8017#section-8
func DecryptRSAESPKCS1V15(key *rsa.PrivateKey, encrypted []byte) ([]byte, error) {
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, key, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt RSAES-PKCS1-v1.5: %w", err)
	}

	return decrypted, nil
}
