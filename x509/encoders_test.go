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

func TestEncodeJWAString(t *testing.T) {
	certs := []*x509.Certificate{
		testcerts.ChainExampleLeaf,
		testcerts.ChainExampleIntermediate,
	}

	encoded := jwx509.EncodeEmbedded(certs)
	require.NotEmpty(t, encoded)

	decoded, err := jwx509.DecodeEmbedded(encoded)
	require.NoError(t, err)
	require.NoError(t, jwx509.Match(certs, decoded))
}

func TestEncodeRemoteHTTP(t *testing.T) {
	certs := []*x509.Certificate{
		testcerts.ChainExampleLeaf,
		testcerts.ChainExampleIntermediate,
	}

	encoded := jwx509.EncodeRemoteHTTP(certs)
	require.NotEmpty(t, encoded)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	decoded, err := jwx509.DecodeRemoteHTTP(req)
	require.NoError(t, err)
	require.NoError(t, jwx509.Match(certs, decoded))
}

func TestEncodeFiles(t *testing.T) {
	certs := []*x509.Certificate{
		testcerts.ChainExampleLeaf,
		testcerts.ChainExampleIntermediate,
	}

	encoded := jwx509.EncodeFiles(certs)
	require.NotEmpty(t, encoded)

	decoded, err := jwx509.DecodeFiles(encoded...)
	require.NoError(t, err)
	require.NoError(t, jwx509.Match(certs, decoded))
}
