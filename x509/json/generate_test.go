package jw509json_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	testcerts "github.com/a-novel-kit/jwt-core/internal/certs"
	"github.com/a-novel-kit/jwt-core/jwa"
	jw509json "github.com/a-novel-kit/jwt-core/x509/json"
)

func TestGenerate(t *testing.T) {
	defaultChain := []*x509.Certificate{
		testcerts.ChainExampleLeaf,
		testcerts.ChainExampleIntermediate,
	}

	defaultSha1 := sha1.Sum(testcerts.ChainExampleLeaf.Raw)
	defaultSha256 := sha256.Sum256(testcerts.ChainExampleLeaf.Raw)

	testCases := []struct {
		name string

		src    []*x509.Certificate
		config *jw509json.GenerateConfig

		expect    *jwa.J509
		expectErr error
	}{
		{
			name: "embed",

			src:    defaultChain,
			config: &jw509json.GenerateConfig{Embed: true},

			expect: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
			},
		},
		{
			name: "with thumbprints",

			src:    defaultChain,
			config: &jw509json.GenerateConfig{Thumbprint: true, Thumbprint256: true},

			expect: &jwa.J509{
				X5T:    base64.RawURLEncoding.EncodeToString(defaultSha1[:]),
				X5T256: base64.RawURLEncoding.EncodeToString(defaultSha256[:]),
			},
		},
		{
			name: "with serving URL",

			src:    defaultChain,
			config: &jw509json.GenerateConfig{Serve: "https://example.com/certificates"},

			expect: &jwa.J509{
				X5U: "https://example.com/certificates",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			payload, err := jw509json.Generate(testCase.src, testCase.config)
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expect, payload)
		})
	}
}
