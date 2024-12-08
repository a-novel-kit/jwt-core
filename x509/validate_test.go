package jwx509_test

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	testcerts "github.com/a-novel-kit/jwt-core/internal/certs"
	jwx509 "github.com/a-novel-kit/jwt-core/x509"
)

func Validate(t *testing.T) {
	testCases := []struct {
		name string

		certs []*x509.Certificate
		opts  *jwx509.ValidateConfig

		expectErr bool
	}{
		{
			name: "valid certs",

			certs: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},

			opts: &jwx509.ValidateConfig{
				Roots: testcerts.Roots,
			},
		},
		{
			name: "invalid certs",

			certs: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.CertRSA2048,
			},

			opts: &jwx509.ValidateConfig{
				Roots: testcerts.Roots,
			},

			expectErr: true,
		},
		{
			name: "with hostname",

			certs: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},

			opts: &jwx509.ValidateConfig{
				Roots:            testcerts.Roots,
				TrustedHostnames: []string{"abc.def.hij", "www.example.com"},
			},
		},
		{
			name: "with invalid hostname",

			certs: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},

			opts: &jwx509.ValidateConfig{
				Roots:            testcerts.Roots,
				TrustedHostnames: []string{"abc.def.hij"},
			},

			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := jwx509.Validate(testCase.certs, testCase.opts)
			require.True(t, (err != nil) == testCase.expectErr, err)
		})
	}
}
