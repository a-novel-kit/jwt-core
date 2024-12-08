package jwkgen_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestGenerateED25519(t *testing.T) {
	privKey1, pubKey1, err := jwkgen.ED25519()
	require.NoError(t, err)

	privKey2, pubKey2, err := jwkgen.ED25519()
	require.NoError(t, err)

	require.NotEqual(t, privKey1, privKey2)
	require.NotEqual(t, pubKey1, pubKey2)
}
