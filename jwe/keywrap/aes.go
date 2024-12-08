package keywrap

import (
	"crypto/aes"
	"fmt"

	jweutils "github.com/a-novel-kit/jwt-core/jwe/utils"
)

// WrapAES takes 2 keys: a Key Wrapping Key (KWK) and a Content Encryption Key (CEK).
// It then wraps the CEK using the KWK and returns the wrapped key (JWRK).
func WrapAES(kwk, cek []byte) ([]byte, error) {
	// Funny name.
	block, err := aes.NewCipher(kwk)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	jwrk, err := jweutils.KeyWrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("key wrap: %w", err)
	}

	return jwrk, nil
}

// UnwrapAES takes 2 keys: a Key Wrapping Key (KWK) and a JWE Wrapped Key (JWRK).
// It then unwraps the JEK using the KWK and returns the unwrapped key (CEK).
func UnwrapAES(kwk, jwrk []byte) ([]byte, error) {
	block, err := aes.NewCipher(kwk)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	cek, err := jweutils.KeyUnwrap(block, jwrk)
	if err != nil {
		return nil, fmt.Errorf("key unwrap: %w", err)
	}

	return cek, nil
}
