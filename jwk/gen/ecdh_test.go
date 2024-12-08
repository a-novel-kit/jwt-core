package jwkgen_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestGenerateX25519(t *testing.T) {
	privKey1, err := jwkgen.X25519()
	require.NoError(t, err)

	privKey2, err := jwkgen.X25519()
	require.NoError(t, err)

	require.NotEqual(t, privKey1, privKey2)
}
