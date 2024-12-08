package jwkgen_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestGenerateHMAC(t *testing.T) {
	key1, err := jwkgen.HMAC(jwkgen.H256KeySize)
	require.NoError(t, err)
	require.Len(t, key1, jwkgen.H256KeySize)

	key2, err := jwkgen.HMAC(jwkgen.H256KeySize)
	require.NoError(t, err)
	require.Len(t, key2, jwkgen.H256KeySize)

	require.NotEqual(t, key1, key2)

	key1, err = jwkgen.HMAC(jwkgen.H384KeySize)
	require.NoError(t, err)
	require.Len(t, key1, jwkgen.H384KeySize)

	key1, err = jwkgen.HMAC(jwkgen.H512KeySize)
	require.NoError(t, err)
	require.Len(t, key1, jwkgen.H512KeySize)
}
