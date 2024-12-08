package jwx509

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidCertHost = errors.New("certificate was not issued for any of the provided hostnames")

type ValidateConfig struct {
	// TrustedHostnames, if present, will ensure the certificates are issued from one of the provided hostnames.
	TrustedHostnames []string
	// Usage specifies which Extended CEK Usage values are acceptable. A chain is accepted if it allows any of the
	// listed values. An empty list means x509.ExtKeyUsageServerAuth. To accept any key usage, include
	// x509.ExtKeyUsageAny.
	Usage []x509.ExtKeyUsage
	// CurrentTime is used to check the validity of all certificates in the chain. If zero, the current time is used.
	CurrentTime time.Time
	// Roots is the set of trusted root certificates the leaf certificate needs to chain up to. If nil, the system
	// roots or the platform verifier are used.
	Roots *x509.CertPool
}

// Validate checks the integrity of a certificate chain.
func Validate(certs []*x509.Certificate, opts *ValidateConfig) error {
	if len(certs) == 0 {
		return nil
	}

	var validHostName string
	var err error
	for _, hostName := range opts.TrustedHostnames {
		if err = certs[0].VerifyHostname(hostName); err == nil {
			validHostName = hostName
			break
		}
	}

	if validHostName == "" && len(opts.TrustedHostnames) > 0 {
		return errors.Join(ErrInvalidCertHost, err)
	}

	certsPool := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			certsPool.AddCert(cert)
		}
	}

	_, err = certs[0].Verify(x509.VerifyOptions{
		DNSName:       validHostName,
		Intermediates: certsPool,
		CurrentTime:   opts.CurrentTime,
		KeyUsages:     opts.Usage,
		Roots:         opts.Roots,
	})
	if err != nil {
		return fmt.Errorf("validate leaf: %w", err)
	}

	return nil
}
