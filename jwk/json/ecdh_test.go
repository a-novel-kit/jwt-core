package jwkjson_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	jwkjson "github.com/a-novel-kit/jwt-core/jwk/json"
)

func TestEncodeDecodeECDHPrivate(t *testing.T) {
	key1, err := jwkgen.X25519()
	require.NoError(t, err)

	encoded, err := jwkjson.EncodeECDH(key1)
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeECDH(encoded)
		require.NoError(t, err)
		require.True(t, key1.Equal(decodedPriv))
		require.True(t, key1.PublicKey().Equal(decodedPub))
	})

	t.Run("decode with error", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeECDH(&jwkjson.ECDHPayload{X: "^%$#"})
		require.Error(t, err)
		require.Nil(t, decodedPriv)
		require.Nil(t, decodedPub)
	})
}

func TestEncodeDecodeECFHPublic(t *testing.T) {
	key1, err := jwkgen.X25519()
	require.NoError(t, err)

	encoded, err := jwkjson.EncodeECDH(key1.PublicKey())
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeECDH(encoded)
		require.NoError(t, err)
		require.Nil(t, decodedPriv)
		require.True(t, key1.PublicKey().Equal(decodedPub))
	})
}
