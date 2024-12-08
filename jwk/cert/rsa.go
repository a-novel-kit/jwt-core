package jwkcert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func EncodeRSA(key *rsa.PrivateKey) []byte {
	encoded := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: encoded,
	}

	return pem.EncodeToMemory(block)
}

func DecodeRSA(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("decode pem block: no block found")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
