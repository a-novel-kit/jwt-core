package jwscore_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	jwscore "github.com/a-novel-kit/jwt-core/jws"
)

func TestSignAndVerifyRSAPSS(t *testing.T) {
	t.Run("SignAndVerify", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.RSA(jwkgen.RS256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		// Generate a second key pair.
		key2, err := jwkgen.RSA(jwkgen.RS256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key2)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jwscore.SignRSAPSS(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jwscore.VerifyRSAPSS(strToSign, signature, &key.PublicKey, crypto.SHA256)
		require.NoError(t, err)

		// Verify the signature with a wrong key.
		err = jwscore.VerifyRSAPSS(strToSign, signature, &key2.PublicKey, crypto.SHA256)
		require.ErrorIs(t, err, jwscore.ErrInvalidSignature)
	})

	t.Run("VerifyWithWrongSHA", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.RSA(jwkgen.RS256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jwscore.SignRSAPSS(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jwscore.VerifyRSAPSS(strToSign, signature, &key.PublicKey, crypto.SHA3_384)
		require.ErrorIs(t, err, jwscore.ErrInvalidSignature)
	})

	t.Run("DataTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.RSA(jwkgen.RS256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jwscore.SignRSAPSS(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jwscore.VerifyRSAPSS(strToSign+"foo", signature, &key.PublicKey, crypto.SHA3_384)
		require.ErrorIs(t, err, jwscore.ErrInvalidSignature)
	})

	t.Run("SignatureTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.RSA(jwkgen.RS256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jwscore.SignRSAPSS(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jwscore.VerifyRSAPSS(strToSign, "&/?.,<>", &key.PublicKey, crypto.SHA3_384)
		require.Error(t, err)
	})
}
