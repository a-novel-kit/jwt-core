package keyenc_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt-core/jwe/keyenc"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestRSAESOAEP(t *testing.T) {
	key, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)
	key2, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)

	cek, err := jwkgen.AES(jwkgen.AESKeySize512)
	require.NoError(t, err)

	encrypted, err := keyenc.EncryptRSAESOAEP(&key.PublicKey, sha1.New(), cek)
	require.NoError(t, err)

	decrypted, err := keyenc.DecryptRSAESOAEP(key, sha1.New(), encrypted)
	require.NoError(t, err)

	require.Equal(t, cek, decrypted)

	t.Run("invalid key", func(t *testing.T) {
		_, err := keyenc.DecryptRSAESOAEP(key2, sha1.New(), encrypted)
		require.Error(t, err)
	})
}

func TestRSAESOAEP256(t *testing.T) {
	key, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)
	key2, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)

	cek, err := jwkgen.AES(jwkgen.AESKeySize512)
	require.NoError(t, err)

	encrypted, err := keyenc.EncryptRSAESOAEP(&key.PublicKey, sha256.New(), cek)
	require.NoError(t, err)

	decrypted, err := keyenc.DecryptRSAESOAEP(key, sha256.New(), encrypted)
	require.NoError(t, err)

	require.Equal(t, cek, decrypted)

	t.Run("invalid key", func(t *testing.T) {
		_, err := keyenc.DecryptRSAESOAEP(key2, sha256.New(), encrypted)
		require.Error(t, err)
	})
}
