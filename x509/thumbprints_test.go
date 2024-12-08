package jwx509_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	testcerts "github.com/a-novel-kit/jwt-core/internal/certs"
	jwx509 "github.com/a-novel-kit/jwt-core/x509"
)

func TestMatchThumbprint(t *testing.T) {
	sha1Thumprint2048 := sha1.Sum(testcerts.CertRSA2048.Raw)
	sha1Thumprint4096 := sha1.Sum(testcerts.CertRSA4096.Raw)

	sha256Thumprint2048 := sha256.Sum256(testcerts.CertRSA2048.Raw)

	testCases := []struct {
		name string

		certs      []*x509.Certificate
		thumbprint []byte

		expect error
	}{
		{
			name: "sha1",

			certs:      []*x509.Certificate{testcerts.CertRSA2048},
			thumbprint: sha1Thumprint2048[:],
		},
		{
			name: "sha1 mismatch",

			certs:      []*x509.Certificate{testcerts.CertRSA2048},
			thumbprint: sha1Thumprint4096[:],

			expect: jwx509.ErrThumbprintMismatch,
		},
		{
			name: "sha256",

			certs:      []*x509.Certificate{testcerts.CertRSA2048},
			thumbprint: sha256Thumprint2048[:],
		},
		{
			name: "no certs",

			certs:      []*x509.Certificate{},
			thumbprint: sha256Thumprint2048[:],

			expect: jwx509.ErrNoCerts,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := jwx509.MatchThumbprint(testCase.certs, testCase.thumbprint)
			require.ErrorIs(t, err, testCase.expect)
		})
	}
}
