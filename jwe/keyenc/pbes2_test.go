package keyenc_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt-core/jwe/keyenc"
)

// https://datatracker.ietf.org/doc/html/rfc7517#appendix-C
func TestDerivePBES2(t *testing.T) {
	salt := []byte{
		80, 66, 69, 83, 50, 45, 72, 83, 50, 53, 54, 43, 65, 49, 50, 56, 75,
		87, 0, 217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174,
		42, 80, 215,
	}

	iter := 4096

	passphrase := []byte{
		84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108,
		105, 112, 115, 44, 32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32,
		109, 121, 32, 115, 105, 110, 32, 105, 115, 32, 112, 117, 114, 103,
		101, 100, 46,
	}

	expected := []byte{
		110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14,
		24, 75,
	}

	res, err := keyenc.DerivePBES2(crypto.SHA256, salt, passphrase, iter)
	require.NoError(t, err)
	require.Equal(t, expected, res)
}
