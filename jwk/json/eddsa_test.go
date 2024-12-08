package jwkjson_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	jwkjson "github.com/a-novel-kit/jwt-core/jwk/json"
)

func TestEncodeDecodeEDPrivate(t *testing.T) {
	privKey, pubKey, err := jwkgen.ED25519()
	require.NoError(t, err)

	encoded := jwkjson.EncodeED(privKey)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeED(encoded)
		require.NoError(t, err)
		require.Equal(t, privKey, decodedPriv)
		require.Equal(t, pubKey, decodedPub)
	})

	t.Run("decode with error", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeED(&jwkjson.EDPayload{X: "^%$#"})
		require.Error(t, err)
		require.Nil(t, decodedPriv)
		require.Nil(t, decodedPub)
	})
}

func TestEncodeDecodeEDPublic(t *testing.T) {
	_, pubKey, err := jwkgen.ED25519()
	require.NoError(t, err)

	encoded := jwkjson.EncodeED(pubKey)
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		decodedPriv, decodedPub, err := jwkjson.DecodeED(encoded)
		require.NoError(t, err)
		require.Nil(t, decodedPriv)
		require.Equal(t, pubKey, decodedPub)
	})
}
