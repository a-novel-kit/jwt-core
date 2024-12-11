package jwkgen

import (
	"crypto/rand"
	"fmt"

	jwkcore "github.com/a-novel-kit/jwt-core/jwk"
)

type AESKeySize int

const (
	AESKeySize128 AESKeySize = 16
	AESKeySize192 AESKeySize = 24
	AESKeySize256 AESKeySize = 32
	AESKeySize384 AESKeySize = 48
	AESKeySize512 AESKeySize = 64
)

// AES creates a new random key that can be used for symmetric encryption.
func AES(keySize AESKeySize) ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	return key, nil
}

type IVSize int

const (
	IVSize96  IVSize = 12
	IVSize128 IVSize = 16
)

// IV creates a new random IV that can be used for symmetric encryption.
func IV(ivSize IVSize) ([]byte, error) {
	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	return iv, nil
}

// AESKeyPreset is a set of parameters that can be used to generate a full AESKeySet.
type AESKeyPreset struct {
	// KeySize is the size of the content encryption key to generate.
	KeySize AESKeySize
	// IVSize is the size of the initialization vector to generate.
	IVSize IVSize
}

// AESKeySet creates a new random key and IV that can be used for symmetric encryption.
func AESKeySet(preset AESKeyPreset) (*jwkcore.AESKeySet, error) {
	key, err := AES(preset.KeySize)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	iv, err := IV(preset.IVSize)
	if err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	return &jwkcore.AESKeySet{
		CEK: key,
		IV:  iv,
	}, nil
}

var (
	A128GCMKeyPreset = AESKeyPreset{
		KeySize: AESKeySize128,
		IVSize:  IVSize96,
	}
	A192GCMKeyPreset = AESKeyPreset{
		KeySize: AESKeySize192,
		IVSize:  IVSize96,
	}
	A256GCMKeyPreset = AESKeyPreset{
		KeySize: AESKeySize256,
		IVSize:  IVSize96,
	}

	A128CBCKeyPreset = AESKeyPreset{
		KeySize: AESKeySize256,
		IVSize:  IVSize128,
	}
	A192CBCKeyPreset = AESKeyPreset{
		KeySize: AESKeySize384,
		IVSize:  IVSize128,
	}
	A256CBCKeyPreset = AESKeyPreset{
		KeySize: AESKeySize512,
		IVSize:  IVSize128,
	}
)
