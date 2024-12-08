package jwx509_test

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	testcerts "github.com/a-novel-kit/jwt-core/internal/certs"
	jwx509 "github.com/a-novel-kit/jwt-core/x509"
)

func TestMatch(t *testing.T) {
	testCases := []struct {
		name string

		chain1 []*x509.Certificate
		chain2 []*x509.Certificate

		expect error
	}{
		{
			name: "equal chains",

			chain1: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
			chain2: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "not same length",

			chain1: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
			},
			chain2: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},

			expect: jwx509.ErrCertMismatch,
		},
		{
			name: "not equal chains",

			chain1: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
			chain2: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.CertRSA2048,
			},

			expect: jwx509.ErrCertMismatch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := jwx509.Match(tc.chain1, tc.chain2)
			require.ErrorIs(t, err, tc.expect)
		})
	}
}

func TestMatchKey(t *testing.T) {
	testCases := []struct {
		name string

		keyPub interface{}
		certs  []*x509.Certificate

		expect error
	}{
		{
			name: "valid keys",

			keyPub: testcerts.ChainExampleLeaf.PublicKey,
			certs: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "empty keys",

			keyPub: nil,
			certs:  []*x509.Certificate{},
		},
		{
			name: "invalid keys",

			keyPub: testcerts.CertRSA2048.PublicKey,
			certs: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},

			expect: jwx509.ErrCertKeyMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := jwx509.MatchKey(testCase.keyPub, testCase.certs)
			require.ErrorIs(t, err, testCase.expect)
		})
	}
}
