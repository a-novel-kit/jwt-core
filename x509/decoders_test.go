package jwx509_test

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	testcerts "github.com/a-novel-kit/jwt-core/internal/certs"
	jwx509 "github.com/a-novel-kit/jwt-core/x509"
)

func TestDecodeJWAString(t *testing.T) {
	testCases := []struct {
		name string

		chain []string

		expect []*x509.Certificate

		expectErr bool
	}{
		{
			name: "valid chain",

			chain: []string{
				testcerts.ChainExampleLeafB64,
				testcerts.ChainExampleIntermediateB64,
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "empty chain",

			chain: []string{},

			expect: []*x509.Certificate{},
		},
		{
			name: "chain contains non-x509 certificate",

			chain: []string{
				"foobar",
				testcerts.ChainExampleIntermediateB64,
			},

			expectErr: true,
		},
		{
			name: "chain contains illegal base64",

			chain: []string{
				"foo&^%bar",
				testcerts.ChainExampleIntermediateB64,
			},

			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			out, err := jwx509.DecodeEmbedded(testCase.chain)
			require.True(t, (err != nil) == testCase.expectErr, err)
			require.NoError(t, jwx509.Match(out, testCase.expect))
		})
	}
}

func TestDecodeRemoteHTTP(t *testing.T) {
	testCases := []struct {
		name string

		serverResp     []byte
		serverRespCode int

		expect    []*x509.Certificate
		expectErr bool
	}{
		{
			name: "valid chain",

			serverResp: append(
				testcerts.ChainExampleLeafPEM,
				testcerts.ChainExampleIntermediatePEM...,
			),
			serverRespCode: http.StatusOK,

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "empty chain",

			serverResp:     []byte{},
			serverRespCode: http.StatusOK,

			expect: []*x509.Certificate{},
		},
		{
			name: "chain contains non-x509 certificate",

			serverResp: append(
				testcerts.ChainExampleLeafPEM,
				testcerts.ChainExampleIntermediateKeyPEM...,
			),
			serverRespCode: http.StatusOK,

			expectErr: true,
		},
		{
			name: "server error",

			serverRespCode: http.StatusInternalServerError,

			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Setup a server.
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(testCase.serverRespCode)
				_, _ = w.Write(testCase.serverResp)
			})

			server := httptest.NewServer(handler)
			defer server.Close()

			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			require.NoError(t, err)
			out, err := jwx509.DecodeRemoteHTTP(req)
			require.True(t, (err != nil) == testCase.expectErr, err)
			require.NoError(t, jwx509.Match(out, testCase.expect))
		})
	}
}

func TestDecodeFiles(t *testing.T) {
	testCases := []struct {
		name string

		files [][]byte

		expect    []*x509.Certificate
		expectErr bool
	}{
		{
			name: "valid chain",

			files: [][]byte{
				testcerts.ChainExampleLeafPEM,
				testcerts.ChainExampleIntermediatePEM,
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "empty chain",

			files: [][]byte{},

			expect: []*x509.Certificate{},
		},
		{
			name: "chain contains non-x509 certificate",

			files: [][]byte{
				testcerts.ChainExampleLeafPEM,
				testcerts.ChainExampleIntermediateKeyPEM,
			},

			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			out, err := jwx509.DecodeFiles(testCase.files...)
			require.True(t, (err != nil) == testCase.expectErr, err)
			require.NoError(t, jwx509.Match(out, testCase.expect))
		})
	}
}
