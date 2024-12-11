package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	jwkcore "github.com/a-novel-kit/jwt-core/jwk"
)

// EncryptAESGCM encrypts the payload using AES-GCM. It returns (in order)
// the encrypted payload and the authentication tag.
//
// Additional data is an optional parameter that can be used to pass unencrypted data to the payload.
func EncryptAESGCM(payload, additionalData []byte, key *jwkcore.AESKeySet) (*AESPayload, error) {
	switch len(key.CEK) {
	case 16, 24, 32:
	default:
		return nil, errors.New("unsupported key size")
	}

	// The requested size of the Authentication Tag output MUST be 128 bits,
	// regardless of the key size.
	block, err := aes.NewCipher(key.CEK)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	out := aesgcm.Seal(nil, key.IV, payload, additionalData)

	ciphertext := out[:len(out)-aesgcm.Overhead()]
	tag := out[len(out)-aesgcm.Overhead():]

	if len(tag) != 16 {
		return nil, errors.New("invalid tag size")
	}

	return &AESPayload{
		E: ciphertext,
		T: tag,
	}, nil
}

// DecryptAESGCM decrypts the payload using AES-GCM. It returns the decrypted payload.
func DecryptAESGCM(data *AESPayload, additionalData []byte, key *jwkcore.AESKeySet) ([]byte, error) {
	switch len(key.CEK) {
	case 16, 24, 32:
	default:
		return nil, errors.New("unsupported key size")
	}

	// The requested size of the Authentication Tag output MUST be 128 bits,
	// regardless of the key size.
	block, err := aes.NewCipher(key.CEK)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	if len(data.E)+len(data.T) < aesgcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	ciphertext := data.E
	tag := data.T

	if len(tag) != 16 {
		return nil, errors.New("invalid tag size")
	}

	plaintext, err := aesgcm.Open(nil, key.IV, append(ciphertext, tag...), additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
