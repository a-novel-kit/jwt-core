package keywrap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt-core/jwe/keywrap"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestAES(t *testing.T) {
	cek, err := jwkgen.AES(jwkgen.AESKeySize512)
	require.NoError(t, err)

	kwk, err := jwkgen.AES(jwkgen.AESKeySize256)
	require.NoError(t, err)

	t.Run("aes key wrap", func(t *testing.T) {
		jwrk, err := keywrap.WrapAES(kwk, cek)
		require.NoError(t, err)

		unwrapped, err := keywrap.UnwrapAES(kwk, jwrk)
		require.NoError(t, err)

		require.Equal(t, cek, unwrapped)
	})
}
