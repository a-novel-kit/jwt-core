package jw509json_test

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"

	testcerts "github.com/a-novel-kit/jwt-core/internal/certs"
	"github.com/a-novel-kit/jwt-core/jwa"
	jwx509 "github.com/a-novel-kit/jwt-core/x509"
	jw509json "github.com/a-novel-kit/jwt-core/x509/json"
)

func TestVerify(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cert-chain-1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(append(
				testcerts.ChainExampleLeafPEM,
				testcerts.ChainExampleIntermediatePEM...,
			))
		case "/cert-chain-2":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(testcerts.CertRSA2048PEM)
		}

		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	chainLeafThumbSha1 := sha1.Sum(testcerts.ChainExampleLeaf.Raw)
	chainLeafThumbSha256 := sha256.Sum256(testcerts.ChainExampleLeaf.Raw)

	cert2048Sha1 := sha1.Sum(testcerts.CertRSA2048.Raw)
	cert2048Sha256 := sha256.Sum256(testcerts.CertRSA2048.Raw)

	testCases := []struct {
		name string

		src    *jwa.J509
		config *jw509json.VerifyConfig

		expect    []*x509.Certificate
		expectErr error
	}{
		{
			name: "local",

			src: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "url",

			src: &jwa.J509{
				X5U: server.URL + "/cert-chain-1",
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "local + url",

			src: &jwa.J509{
				X5U: server.URL + "/cert-chain-1",
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "thumbprint sha1",

			src: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
				X5T: base64.RawURLEncoding.EncodeToString(chainLeafThumbSha1[:]),
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "thumbprint sha256",

			src: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
				X5T256: base64.RawURLEncoding.EncodeToString(chainLeafThumbSha256[:]),
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},
		{
			name: "validate certs",

			src: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
				Validate: &jwx509.ValidateConfig{
					Roots: testcerts.Roots,
				},
			},

			expect: []*x509.Certificate{
				testcerts.ChainExampleLeaf,
				testcerts.ChainExampleIntermediate,
			},
		},

		{
			name: "no certs",

			src: &jwa.J509{},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expectErr: jw509json.ErrNoCert,
		},
		{
			name: "local + url mismatch",

			src: &jwa.J509{
				X5U: server.URL + "/cert-chain-2",
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expectErr: certdeck.ErrCertMismatch,
		},
		{
			name: "invalid jwa string",

			src: &jwa.J509{
				X5C: []string{
					"%$#@",
					testcerts.ChainExampleIntermediateB64,
				},
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expectErr: base64.CorruptInputError(0),
		},
		{
			name: "server error",

			src: &jwa.J509{
				X5U: server.URL + "/foo-bar",
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expectErr: jw509json.ErrUnexpectedStatus,
		},
		{
			name: "invalid thumbprint sha1",

			src: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
				X5T: base64.RawURLEncoding.EncodeToString(cert2048Sha1[:]),
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expectErr: jwx509.ErrThumbprintMismatch,
		},
		{
			name: "invalid thumbprint sha256",

			src: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
				X5T256: base64.RawURLEncoding.EncodeToString(cert2048Sha256[:]),
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
			},

			expectErr: jwx509.ErrThumbprintMismatch,
		},
		{
			name: "validate certs fail",

			src: &jwa.J509{
				X5C: []string{
					testcerts.ChainExampleLeafB64,
					testcerts.ChainExampleIntermediateB64,
				},
			},
			config: &jw509json.VerifyConfig{
				ReqFactory: jw509json.RequestFactoryDefault,
				Validate: &jwx509.ValidateConfig{
					Roots:            testcerts.Roots,
					TrustedHostnames: []string{"abc.def.hij"},
				},
			},

			expectErr: jwx509.ErrInvalidCertHost,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			res, err := jw509json.Verify(context.Background(), testCase.src, testCase.config)
			require.ErrorIs(t, err, testCase.expectErr)
			require.NoError(t, certdeck.Match(res, testCase.expect))
		})
	}
}
