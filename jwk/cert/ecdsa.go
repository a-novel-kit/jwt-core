package jwkcert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func EncodeECDSA(key *ecdsa.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ecdsa private key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: encoded,
	}

	return pem.EncodeToMemory(block), nil
}

func DecodeECDSA(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("decode pem block: no block found")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}
