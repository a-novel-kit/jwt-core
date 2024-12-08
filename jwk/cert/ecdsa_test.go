package jwkcert_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	jwkcert "github.com/a-novel-kit/jwt-core/jwk/cert"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestECDSA(t *testing.T) {
	key, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)

	encoded, err := jwkcert.EncodeECDSA(key)
	require.NoError(t, err)

	rsaKey, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)

	rsaEncoded := jwkcert.EncodeRSA(rsaKey)

	t.Run("decode", func(t *testing.T) {
		decoded, err := jwkcert.DecodeECDSA(encoded)
		require.NoError(t, err)

		require.True(t, key.Equal(decoded))
	})

	t.Run("decode non-RSA key", func(t *testing.T) {
		_, err := jwkcert.DecodeECDSA(rsaEncoded)
		require.Error(t, err)
	})

	t.Run("decode empty block", func(t *testing.T) {
		_, err := jwkcert.DecodeECDSA([]byte{})
		require.Error(t, err)
	})
}
