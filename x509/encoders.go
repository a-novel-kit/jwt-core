package jwx509

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// EncodeEmbedded encodes a chain of x509.Certificate objects into a slice of base64-encoded strings.
func EncodeEmbedded(chain []*x509.Certificate) []string {
	out := make([]string, len(chain))

	for pos, cert := range chain {
		out[pos] = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	return out
}

// EncodeRemoteHTTP encodes a chain of x509.Certificate objects into a single PEM-encoded byte slice, that can be
// served over an HTTP server.
func EncodeRemoteHTTP(chain []*x509.Certificate) []byte {
	out := make([]byte, 0)

	for _, cert := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	return out
}

// EncodeFiles encodes a chain of x509.Certificate objects into a slice of PEM-encoded byte slices.
func EncodeFiles(chain []*x509.Certificate) [][]byte {
	out := make([][]byte, len(chain))

	for pos, cert := range chain {
		out[pos] = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}

	return out
}
