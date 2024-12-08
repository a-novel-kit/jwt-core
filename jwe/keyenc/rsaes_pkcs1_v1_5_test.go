package keyenc_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt-core/jwe/keyenc"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestRSAESPKCS1V15(t *testing.T) {
	key, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)
	key2, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)

	cek, err := jwkgen.AES(jwkgen.AESKeySize512)
	require.NoError(t, err)

	encrypted, err := keyenc.EncryptRSAESPKCS1V15(&key.PublicKey, cek)
	require.NoError(t, err)

	decrypted, err := keyenc.DecryptRSAESPKCS1V15(key, encrypted)
	require.NoError(t, err)

	require.Equal(t, cek, decrypted)

	t.Run("invalid key", func(t *testing.T) {
		_, err := keyenc.DecryptRSAESPKCS1V15(key2, encrypted)
		require.Error(t, err)
	})
}
