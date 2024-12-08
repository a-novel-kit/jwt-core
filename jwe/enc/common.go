package enc

// AESPayload represents the result of an AES encryption.
type AESPayload struct {
	// E is the encrypted data.
	E []byte
	// T is the authentication tag.
	T []byte
}
