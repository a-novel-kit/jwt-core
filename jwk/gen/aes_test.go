package jwkgen_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

func TestGenerateAESKey(t *testing.T) {
	testCases := []struct {
		name string

		keySize jwkgen.AESKeySize

		expectLength int
		expectErr    bool
	}{
		{
			name:         "AES 128 bits key",
			keySize:      jwkgen.AESKeySize128,
			expectLength: 16,
		},
		{
			name:         "AES 192 bits key",
			keySize:      jwkgen.AESKeySize192,
			expectLength: 24,
		},
		{
			name:         "AES 256 bits key",
			keySize:      jwkgen.AESKeySize256,
			expectLength: 32,
		},
		{
			name:         "AES 384 bits key",
			keySize:      jwkgen.AESKeySize384,
			expectLength: 48,
		},
		{
			name:         "AES 512 bits key",
			keySize:      jwkgen.AESKeySize512,
			expectLength: 64,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			key, err := jwkgen.AES(testCase.keySize)
			require.Equal(t, testCase.expectErr, err != nil)
			require.NoError(t, err)
			require.Len(t, key, testCase.expectLength)
		})
	}
}

func TestGenerateIV(t *testing.T) {
	testCases := []struct {
		name string

		ivSize jwkgen.IVSize

		expectLength int
		expectErr    bool
	}{
		{
			name:         "IV 96 bits",
			ivSize:       jwkgen.IVSize96,
			expectLength: 12,
		},
		{
			name:         "IV 128 bits",
			ivSize:       jwkgen.IVSize128,
			expectLength: 16,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			iv, err := jwkgen.IV(testCase.ivSize)
			require.Equal(t, testCase.expectErr, err != nil)
			require.NoError(t, err)
			require.Len(t, iv, testCase.expectLength)
		})
	}
}

func TestGenerateAESKeySet(t *testing.T) {
	testCases := []struct {
		name string

		preset jwkgen.AESKeyPreset

		expectKeyLength int
		expectIVLength  int
		expectErr       bool
	}{
		{
			name:            "A128CBC",
			preset:          jwkgen.A128CBCKeyPreset,
			expectKeyLength: 32,
			expectIVLength:  16,
		},
		{
			name:            "A192CBC",
			preset:          jwkgen.A192CBCKeyPreset,
			expectKeyLength: 48,
			expectIVLength:  16,
		},
		{
			name:            "A256CBC",
			preset:          jwkgen.A256CBCKeyPreset,
			expectKeyLength: 64,
			expectIVLength:  16,
		},

		{
			name:            "A128GCM",
			preset:          jwkgen.A128GCMKeyPreset,
			expectKeyLength: 16,
			expectIVLength:  12,
		},
		{
			name:            "A192GCM",
			preset:          jwkgen.A192GCMKeyPreset,
			expectKeyLength: 24,
			expectIVLength:  12,
		},
		{
			name:            "A256GCM",
			preset:          jwkgen.A256GCMKeyPreset,
			expectKeyLength: 32,
			expectIVLength:  12,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			keySet, err := jwkgen.AESKeySet(testCase.preset)
			require.Equal(t, testCase.expectErr, err != nil)
			require.NoError(t, err)
			require.Len(t, keySet.CEK, testCase.expectKeyLength)
			require.Len(t, keySet.IV, testCase.expectIVLength)
		})
	}
}
