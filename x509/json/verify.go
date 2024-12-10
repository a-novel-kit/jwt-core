package jw509json

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/net/context"

	"github.com/a-novel-kit/certdeck"

	"github.com/a-novel-kit/jwt-core/jwa"
	jwx509 "github.com/a-novel-kit/jwt-core/x509"
)

var (
	ErrNoCert           = errors.New("no certificate chain provided")
	ErrUnexpectedStatus = errors.New("unexpected status code")
)

type VerifyConfig struct {
	// Validate is an optional config to ensure the certificate chain is valid.
	Validate *jwx509.ValidateConfig
	// ReqFactory is a function to create the request to fetch the remote certificate chain.
	//
	// While required, you can use the default RequestFactoryDefault for faster setup. This is however not recommended,
	// as the URL that serves your certificates must provide a layer of security that should be embedded in that
	// request.
	ReqFactory func(ctx context.Context, src *jwa.J509) (*http.Request, error)
}

func RequestFactoryDefault(ctx context.Context, src *jwa.J509) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodGet, src.X5U, nil)
}

// Verify ensures the represented certificate chain is valid.
func Verify(ctx context.Context, src *jwa.J509, config *VerifyConfig) ([]*x509.Certificate, error) {
	var localChain, remoteChain, chain []*x509.Certificate
	var err error

	if len(src.X5C) > 0 {
		localChain, err = certdeck.Base64ToCerts(src.X5C)
		if err != nil {
			return nil, fmt.Errorf("decode certificate chain: %w", err)
		}

		chain = localChain
	}

	if src.X5U != "" {
		request, err := config.ReqFactory(ctx, src)
		if err != nil {
			return nil, fmt.Errorf("create x5u request: %w", err)
		}

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("fetch remote certificate chain: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("fetch remote certificate chain: %w", ErrUnexpectedStatus)
		}

		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read remote certificate chain: %w", err)
		}

		remoteChain, err = certdeck.PEMInlineToCerts(data)
		if err != nil {
			return nil, fmt.Errorf("decode remote certificate chain: %w", err)
		}

		chain = remoteChain
	}

	if len(localChain) == 0 && len(remoteChain) == 0 {
		return nil, ErrNoCert
	}

	if len(localChain) > 0 && len(remoteChain) > 0 {
		if err := certdeck.Match(localChain, remoteChain); err != nil {
			return nil, fmt.Errorf("certificate chain mismatch: %w", err)
		}
	}

	if len(src.X5T) > 0 {
		x5tSHA1bytes, err := base64.RawURLEncoding.DecodeString(src.X5T)
		if err != nil {
			return nil, fmt.Errorf("decode x5t: %w", err)
		}

		if err := jwx509.MatchThumbprint(chain, x5tSHA1bytes); err != nil {
			return nil, fmt.Errorf("sha1 thumbprint mismatch: %w", err)
		}
	}

	if len(src.X5T256) > 0 {
		x5tSHA256bytes, err := base64.RawURLEncoding.DecodeString(src.X5T256)
		if err != nil {
			return nil, fmt.Errorf("decode x5t256: %w", err)
		}

		if err := jwx509.MatchThumbprint(chain, x5tSHA256bytes); err != nil {
			return nil, fmt.Errorf("sha256 thumbprint mismatch: %w", err)
		}
	}

	if config.Validate != nil {
		if err := jwx509.Validate(chain, config.Validate); err != nil {
			return nil, fmt.Errorf("validate certificate chain: %w", err)
		}
	}

	return chain, nil
}
