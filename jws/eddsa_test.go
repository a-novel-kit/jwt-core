package jwscore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	jwscore "github.com/a-novel-kit/jwt-core/jws"
)

func TestSignAndVerifyED25519(t *testing.T) {
	t.Run("SignAndVerify", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		privKey1, pubKey1, err := jwkgen.ED25519()
		require.NoError(t, err)

		// Generate a second key pair.
		_, pubKey2, err := jwkgen.ED25519()
		require.NoError(t, err)

		strToSign := "Hello, World!"

		// Sign the string.
		signature := jwscore.SignED25519(strToSign, privKey1)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jwscore.VerifyED25519(strToSign, signature, pubKey1)
		require.NoError(t, err)

		// Verify the signature with a wrong key.
		err = jwscore.VerifyED25519(strToSign, signature, pubKey2)
		require.ErrorIs(t, err, jwscore.ErrInvalidSignature)
	})

	t.Run("DataTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		privKey, pubKey, err := jwkgen.ED25519()
		require.NoError(t, err)

		strToSign := "Hello, World!"

		// Sign the string.
		signature := jwscore.SignED25519(strToSign, privKey)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jwscore.VerifyED25519(strToSign+"foo", signature, pubKey)
		require.ErrorIs(t, err, jwscore.ErrInvalidSignature)
	})

	t.Run("SignatureTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		privKey, pubKey, err := jwkgen.ED25519()
		require.NoError(t, err)

		strToSign := "Hello, World!"

		// Sign the string.
		signature := jwscore.SignED25519(strToSign, privKey)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jwscore.VerifyED25519(strToSign, "&/?.,<>", pubKey)
		require.Error(t, err)
	})
}
