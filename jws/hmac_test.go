package jws_test

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
	"github.com/a-novel-kit/jwt-core/jws"
)

func TestSignAndVerifyHMAC(t *testing.T) {
	t.Run("SignAndVerify", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.HMAC(jwkgen.H256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		// Generate a second key pair.
		key2, err := jwkgen.HMAC(jwkgen.H256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key2)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jws.SignHMAC(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jws.VerifyHMAC(strToSign, signature, key, crypto.SHA256)
		require.NoError(t, err)

		// Verify the signature with a wrong key.
		err = jws.VerifyHMAC(strToSign, signature, key2, crypto.SHA256)
		require.ErrorIs(t, err, jws.ErrInvalidSignature)
	})

	t.Run("VerifyWithWrongSHA", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.HMAC(jwkgen.H256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jws.SignHMAC(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jws.VerifyHMAC(strToSign, signature, key, crypto.SHA3_384)
		require.ErrorIs(t, err, jws.ErrInvalidSignature)
	})

	t.Run("DataTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.HMAC(jwkgen.H256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jws.SignHMAC(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jws.VerifyHMAC(strToSign+"foo", signature, key, crypto.SHA3_384)
		require.ErrorIs(t, err, jws.ErrInvalidSignature)
	})

	t.Run("SignatureTampered", func(t *testing.T) {
		// Generate a new ECDSA key pair.
		key, err := jwkgen.HMAC(jwkgen.H256KeySize)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		strToSign := "Hello, World!"

		// Sign the string.
		signature, err := jws.SignHMAC(strToSign, key, crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify the signature.
		err = jws.VerifyHMAC(strToSign, "&/?.,<>", key, crypto.SHA3_384)
		require.Error(t, err)
	})
}
