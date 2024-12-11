package jwkcore

type AESKeySet struct {
	// CEK is the content encryption key.
	CEK []byte
	// IV is the initialization vector.
	IV []byte
}
