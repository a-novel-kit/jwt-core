package jwkjson_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	jwkjson "github.com/a-novel-kit/jwt-core/jwk/json"
)

func TestEncodeDecodeRSAPrivate(t *testing.T) {
	key1, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)

	encoded := jwkjson.EncodeRSA(key1)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeRSA(encoded)
		require.NoError(t, err)
		require.True(t, key1.Equal(decodedPriv))
		require.True(t, key1.PublicKey.Equal(decodedPub))
	})

	t.Run("decode with error", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeRSA(&jwkjson.RSAPayload{N: "^%$#"})
		require.Error(t, err)
		require.Nil(t, decodedPriv)
		require.Nil(t, decodedPub)
	})
}

func TestEncodeDecodeRSAPublic(t *testing.T) {
	key1, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)

	encoded := jwkjson.EncodeRSA(&key1.PublicKey)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeRSA(encoded)
		require.NoError(t, err)
		require.Nil(t, decodedPriv)
		require.True(t, key1.PublicKey.Equal(decodedPub))
	})
}
