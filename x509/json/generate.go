package jw509json

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	"github.com/a-novel-kit/jwt-core/jwa"
)

type GenerateConfig struct {
	// Embed embeds the certificate chain in the JWT.
	Embed bool
	// Serve indicates a URL on which certificates will be served.
	Serve string

	// Thumbprint generates a sha1 thumbprint of the certificate chain.
	Thumbprint bool
	// Thumbprint256 generates a sha256 thumbprint of the certificate chain.
	Thumbprint256 bool
}

// Generate a new X509 JSON payload for a certificate chain.
func Generate(src []*x509.Certificate, config *GenerateConfig) (*jwa.J509, error) {
	output := &jwa.J509{}

	if config.Embed {
		output.X5C = make([]string, len(src))
		for pos, cert := range src {
			output.X5C[pos] = base64.StdEncoding.EncodeToString(cert.Raw)
		}
	}

	if config.Serve != "" {
		output.X5U = config.Serve
	}

	if config.Thumbprint {
		thumbprint := sha1.Sum(src[0].Raw)
		output.X5T = base64.RawURLEncoding.EncodeToString(thumbprint[:])
	}

	if config.Thumbprint256 {
		thumbprint := sha256.Sum256(src[0].Raw)
		output.X5T256 = base64.RawURLEncoding.EncodeToString(thumbprint[:])
	}

	return output, nil
}
