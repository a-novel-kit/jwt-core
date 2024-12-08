package jwkgen_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestGenerateECDSA(t *testing.T) {
	key1, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)
	require.NotEmpty(t, key1)
	require.Equal(t, 256, key1.Params().BitSize)

	key2, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)
	require.NotEmpty(t, key2)
	require.Equal(t, 256, key2.Params().BitSize)

	require.False(t, key1.Equal(key2))

	key1, err = jwkgen.EC(elliptic.P384())
	require.NoError(t, err)
	require.NotEmpty(t, key1)
	require.Equal(t, 384, key1.Params().BitSize)

	key1, err = jwkgen.EC(elliptic.P521())
	require.NoError(t, err)
	require.NotEmpty(t, key1)
	require.Equal(t, 521, key1.Params().BitSize)
}
