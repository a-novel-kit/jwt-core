package jwkgen_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestGenerateRSA(t *testing.T) {
	key1, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)
	require.NotEmpty(t, key1)
	require.Equal(t, 256, key1.Size())
	require.NotNil(t, key1.Precomputed)

	key2, err := jwkgen.RSA(jwkgen.RS256KeySize)
	require.NoError(t, err)
	require.NotEmpty(t, key2)
	require.Equal(t, 256, key2.Size())
	require.NotNil(t, key2.Precomputed)

	require.False(t, key1.Equal(key2))

	key1, err = jwkgen.RSA(jwkgen.RS384KeySize)
	require.NoError(t, err)
	require.NotEmpty(t, key1)
	require.Equal(t, 384, key1.Size())
	require.NotNil(t, key1.Precomputed)

	key1, err = jwkgen.RSA(jwkgen.RS512KeySize)
	require.NoError(t, err)
	require.NotEmpty(t, key1)
	require.Equal(t, 512, key1.Size())
	require.NotNil(t, key1.Precomputed)
}
