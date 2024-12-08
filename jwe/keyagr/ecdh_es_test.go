package keyagr_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt-core/jwe/keyagr"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestDeriveECDHES(t *testing.T) {
	recipientKey, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)

	fakeRecipientKey, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)

	fakeRecipientKey2, err := jwkgen.EC(elliptic.P521())
	require.NoError(t, err)

	issuerKey, err := jwkgen.EC(elliptic.P256())
	require.NoError(t, err)

	testCases := []struct {
		name string

		alg keyagr.Alg
	}{
		{
			name: "AlgA128CBC",
			alg:  keyagr.AlgA128CBC,
		},
		{
			name: "AlgA192CBC",
			alg:  keyagr.AlgA192CBC,
		},
		{
			name: "AlgA256CBC",
			alg:  keyagr.AlgA256CBC,
		},
		{
			name: "AlgA128GCM",
			alg:  keyagr.AlgA128GCM,
		},
		{
			name: "AlgA192GCM",
			alg:  keyagr.AlgA192GCM,
		},
		{
			name: "AlgA256GCM",
			alg:  keyagr.AlgA256GCM,
		},
		{
			name: "AlgA128KW",
			alg:  keyagr.AlgA128KW,
		},
		{
			name: "AlgA192KW",
			alg:  keyagr.AlgA192KW,
		},
		{
			name: "AlgA256KW",
			alg:  keyagr.AlgA256KW,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			issuerCEK, err := keyagr.DeriveECDHES(issuerKey, &recipientKey.PublicKey, testCase.alg, nil, nil)
			require.NoError(t, err)

			recipientCEK, err := keyagr.DeriveECDHES(recipientKey, &issuerKey.PublicKey, testCase.alg, nil, nil)
			require.NoError(t, err)

			require.Equal(t, issuerCEK, recipientCEK)
		})
	}

	t.Run("incompatible keys", func(t *testing.T) {
		_, err = keyagr.DeriveECDHES(issuerKey, &fakeRecipientKey2.PublicKey, keyagr.AlgA128CBC, nil, nil)
		require.Error(t, err)
	})

	t.Run("mismatching keys", func(t *testing.T) {
		issuerCEK, err := keyagr.DeriveECDHES(issuerKey, &recipientKey.PublicKey, keyagr.AlgA128CBC, nil, nil)
		require.NoError(t, err)

		recipientCEK, err := keyagr.DeriveECDHES(recipientKey, &fakeRecipientKey.PublicKey, keyagr.AlgA128CBC, nil, nil)
		require.NoError(t, err)

		require.NotEqual(t, issuerCEK, recipientCEK)
	})
}
