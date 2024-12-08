package jwkgen

import (
	"crypto/rand"
	"fmt"
)

const (
	// H256KeySize is the recommended key size for HMAC 256 keys.
	//
	// If the key is more than 64 bytes long, it is hashed (using SHA-384) to derive a 32-byte key.
	//
	// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256.-ctor?view=net-9.0
	H256KeySize = 64
	// H384KeySize is the recommended key size for HMAC 384 keys.
	//
	// If the key is more than 128 bytes long, it is hashed (using SHA-384) to derive a 48-byte key.
	//
	// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha384.-ctor?view=net-9.0
	H384KeySize = 128
	// H512KeySize is the recommended key size for HMAC 512 keys.
	//
	// If the key is more than 128 bytes long, it is hashed (using SHA-384) to derive a 64-byte key.
	//
	// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512.-ctor?view=net-9.0
	H512KeySize = 128
)

// HMAC generates a cryptographically secure random byte slice of the given size.
// The generated key can be used to sign a token using HMAC.
//
// You can use the recommended default constants as the size parameter.
//   - H256KeySize
//   - H384KeySize
//   - H512KeySize
func HMAC(size int) ([]byte, error) {
	out := make([]byte, size)

	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}

	return out, nil
}
