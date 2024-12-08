package jwkjson_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	jwkjson "github.com/a-novel-kit/jwt-core/jwk/json"
)

func TestEncodeDecodeOct(t *testing.T) {
	key1, err := jwkgen.HMAC(jwkgen.H256KeySize)
	require.NoError(t, err)

	encoded := jwkjson.EncodeOct(key1)

	t.Run("decode", func(t *testing.T) {
		decoded, err := jwkjson.DecodeOct(encoded)
		require.NoError(t, err)
		require.Equal(t, key1, decoded)
	})

	t.Run("decode with error", func(t *testing.T) {
		decoded, err := jwkjson.DecodeOct(&jwkjson.OctPayload{K: "^%$#"})
		require.Error(t, err)
		require.Nil(t, decoded)
	})
}
