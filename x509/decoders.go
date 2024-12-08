package jwx509

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
)

var ErrUnexpectedStatus = errors.New("unexpected status code")

// DecodeEmbedded reads a chain of base64-encoded certificates and computes the corresponding x509.Certificate objects.
func DecodeEmbedded(chain []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, len(chain))

	for pos, cert := range chain {
		// Decode base64 content.
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, fmt.Errorf("decode certificate: %w", err)
		}

		// Use the std parser.
		out[pos], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
	}

	return out, nil
}

// DecodeRemoteHTTP reads a chain of PEM-encoded certificate files from a remote URL and computes the corresponding
// x509.Certificate objects.
func DecodeRemoteHTTP(req *http.Request) ([]*x509.Certificate, error) {
	// Download the certificate chain.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download certificate chain: %w", err)
	}
	defer resp.Body.Close()

	// Ensure the response is valid.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download certificate chain: %w %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	// Decode raw data.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read certificate chain: %w", err)
	}

	output := make([]*x509.Certificate, 0)

	// https://stackoverflow.com/a/63036480/9021186
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}

			output = append(output, cert)
		default:
			return nil, fmt.Errorf("parse certificate: unexpected PEM block type %s", block.Type)
		}
	}

	return output, nil
}

// DecodeFiles reads a chain of PEM-encoded certificate files and computes the corresponding x509.Certificate objects.
//
// Since the order of certificates in the chain matters, the filenames must be manually provided in order.
func DecodeFiles(files ...[]byte) ([]*x509.Certificate, error) {
	var err error

	out := make([]*x509.Certificate, len(files))

	for pos, raw := range files {
		// Detect if file uses DER or PEM format.
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("decode pem block: no block found")
		}

		// Ensure block has the correct type.
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("parse certificate: unexpected PEM block type %s", block.Type)
		}

		// Use the std parser.
		out[pos], err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
	}

	return out, nil
}
