package jws_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	"github.com/a-novel-kit/jwt-core/jws"
)

func TestSignAndVerifyEC(t *testing.T) {
	t.Run("SignAndVerify", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.EC(elliptic.P256())
		require.NoError(t, err)
		require.NotEmpty(t, key)

		// Generate a second key pair.
		key2, err := jwkgen.EC(elliptic.P256())
		require.NoError(t, err)
		require.NotEmpty(t, key2)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jws.SignEC(strToSign, key)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jws.VerifyEC(strToSign, signature, &key.PublicKey)
		require.NoError(t, err)

		// Verify the signature with a wrong key.
		err = jws.VerifyEC(strToSign, signature, &key2.PublicKey)
		require.ErrorIs(t, err, jws.ErrInvalidSignature)
	})

	t.Run("DataTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.EC(elliptic.P256())
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jws.SignEC(strToSign, key)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jws.VerifyEC(strToSign+"foo", signature, &key.PublicKey)
		require.ErrorIs(t, err, jws.ErrInvalidSignature)
	})

	t.Run("SignatureTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.EC(elliptic.P256())
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jws.SignEC(strToSign, key)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jws.VerifyEC(strToSign, "&/?.,<>", &key.PublicKey)
		require.Error(t, err)
	})
}
