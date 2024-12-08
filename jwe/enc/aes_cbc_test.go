package enc_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt-core/jwe/enc"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestAESCBC(t *testing.T) {
	t.Run("encrypt and decrypt", func(t *testing.T) {
		payload := []byte("uwu omo owo")

		key, err := jwkgen.AESKeySet(jwkgen.A128CBCKeyPreset)
		require.NoError(t, err)

		data, err := enc.EncryptAESCBC(payload, nil, key)
		require.NoError(t, err)

		decrypted, err := enc.DecryptAESCBC(data, nil, key)
		require.NoError(t, err)

		require.Equal(t, payload, decrypted)
	})

	t.Run("with additional data", func(t *testing.T) {
		payload := []byte("uwu omo owo")
		additionalData := []byte("owo omo uwu")

		key, err := jwkgen.AESKeySet(jwkgen.A128CBCKeyPreset)
		require.NoError(t, err)

		data, err := enc.EncryptAESCBC(payload, additionalData, key)
		require.NoError(t, err)

		decrypted, err := enc.DecryptAESCBC(data, additionalData, key)
		require.NoError(t, err)

		require.Equal(t, payload, decrypted)
	})
}
