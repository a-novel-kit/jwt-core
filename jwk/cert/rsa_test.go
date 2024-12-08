package jwkcert_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	jwkcert "github.com/a-novel-kit/jwt-core/jwk/cert"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestRSA(t *testing.T) {
	key, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)

	encoded := jwkcert.EncodeRSA(key)

	ecKey, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)

	ecEncoded, err := jwkcert.EncodeECDSA(ecKey)
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		decoded, err := jwkcert.DecodeRSA(encoded)
		require.NoError(t, err)

		require.True(t, key.Equal(decoded))
	})

	t.Run("decode non-RSA key", func(t *testing.T) {
		_, err := jwkcert.DecodeRSA(ecEncoded)
		require.Error(t, err)
	})

	t.Run("decode empty block", func(t *testing.T) {
		_, err := jwkcert.DecodeRSA([]byte{})
		require.Error(t, err)
	})
}
