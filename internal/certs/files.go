package testcerts

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
)

// Test certificates generated with:
//   make certsgen
//
// This command requires openssl to be installed.
// https://github.com/openssl/openssl?tab=readme-ov-file#download

//go:embed cacert.pem
var CACertPEM []byte

var (
	//go:embed 2048b-rsa-example-cert.pem
	CertRSA2048PEM []byte

	//go:embed 2048b-rsa-example-keypair.pem
	CertRSA2048KeyPEM []byte

	//go:embed 2048b-rsa-example-keypair.der
	CertRSA2048KeyDER []byte

	CertRSA2048B64 string
	RSA2048        *rsa.PrivateKey
	CertRSA2048    *x509.Certificate
)

var (
	//go:embed 4096b-rsa-example-cert.pem
	CertRSA4096PEM []byte

	//go:embed 4096b-rsa-example-keypair.pem
	CertRSA4096KeyPEM []byte

	//go:embed 4096b-rsa-example-keypair.der
	CertRSA4096KeyDER []byte

	CertRSA409B64 string
	RSA4096       *rsa.PrivateKey
	CertRSA4096   *x509.Certificate
)

var (
	//go:embed chain-example-intermediate-cert.pem
	ChainExampleIntermediatePEM []byte

	//go:embed chain-example-intermediate-keypair.pem
	ChainExampleIntermediateKeyPEM []byte

	//go:embed chain-example-intermediate-keypair.der
	ChainExampleIntermediateKeyDER []byte

	ChainExampleIntermediateB64 string
	ChainExampleIntermediate    *x509.Certificate
	ChainExampleIntermediateRSA *rsa.PrivateKey

	//go:embed chain-example-leaf-cert.pem
	ChainExampleLeafPEM []byte

	//go:embed chain-example-leaf-keypair.der
	ChainExampleLeafDER []byte

	ChainExampleLeafB64 string
	ChainExampleLeaf    *x509.Certificate
	ChainExampleLeafRSA *rsa.PrivateKey
)

func loadKey(
	sourcePEM, sourceDER []byte, certificateBase64 *string, certificate **x509.Certificate, key **rsa.PrivateKey,
) {
	decodedKey, err := x509.ParsePKCS8PrivateKey(sourceDER)
	if err != nil {
		panic(err)
	}

	*key = decodedKey.(*rsa.PrivateKey)

	block, _ := pem.Decode(sourcePEM)
	decodedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	*certificate = decodedCert
	*certificateBase64 = base64.StdEncoding.EncodeToString(decodedCert.Raw)
}

var Roots *x509.CertPool

func init() {
	loadKey(CertRSA2048PEM, CertRSA2048KeyDER, &CertRSA2048B64, &CertRSA2048, &RSA2048)
	loadKey(CertRSA4096PEM, CertRSA4096KeyDER, &CertRSA409B64, &CertRSA4096, &RSA4096)

	loadKey(
		ChainExampleIntermediatePEM,
		ChainExampleIntermediateKeyDER,
		&ChainExampleIntermediateB64,
		&ChainExampleIntermediate,
		&ChainExampleIntermediateRSA,
	)
	loadKey(
		ChainExampleLeafPEM,
		ChainExampleLeafDER,
		&ChainExampleLeafB64,
		&ChainExampleLeaf,
		&ChainExampleLeafRSA,
	)

	Roots = x509.NewCertPool()

	block, _ := pem.Decode(CACertPEM)
	if block == nil {
		panic("failed to parse root certificate")
	}

	if !Roots.AppendCertsFromPEM(CACertPEM) {
		panic("failed to append root certificate")
	}
}
