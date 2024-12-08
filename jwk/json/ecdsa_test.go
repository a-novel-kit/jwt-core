package jwkjson_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	jwkjson "github.com/a-novel-kit/jwt-core/jwk/json"
)

func TestEncodeDecodeECPrivate(t *testing.T) {
	key1, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)

	encoded, err := jwkjson.EncodeEC(key1)
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeEC(encoded)
		require.NoError(t, err)
		require.True(t, key1.Equal(decodedPriv))
		require.True(t, key1.PublicKey.Equal(decodedPub))
	})

	t.Run("decode with error", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeEC(&jwkjson.ECPayload{X: "^%$#"})
		require.Error(t, err)
		require.Nil(t, decodedPriv)
		require.Nil(t, decodedPub)
	})
}

func TestEncodeDecodeECPublic(t *testing.T) {
	key1, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)

	encoded, err := jwkjson.EncodeEC(&key1.PublicKey)
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeEC(encoded)
		require.NoError(t, err)
		require.Nil(t, decodedPriv)
		require.True(t, key1.PublicKey.Equal(decodedPub))
	})
}
