# x509

```go
import "github.com/a-novel-kit/jwt-core/x509"
```

Manage certificates using x509 package.

- [Decoders and Encoders](#decoders-and-encoders)
    - [Embedded](#embedded)
    - [URL](#url)
    - [Files](#files)
- [Match](#match)
- [Match Key](#match-key)
- [Thumbprint](#thumbprint)
- [Validate](#validate)
    - [Validate options](#validate-options)

## Decoders and Encoders

The jw509 package lets you load and save x509 certificate chains, from and to JSON Web Algorithm sources. 
Dealing with the JWA representation itself is done in the sibling `jw509json` package.

The JWA docs define 2 sources for x509 certificates:

- **Embedded**: x509 certificates of a chain may be embedded as base64-encoded strings.
- **URL**: a chain of x509 certificates can be served over HTTP. The resource must be a chain of PEM-encoded
	certificates, concatenated into a single bytes array.

Additionally, this package lets you interact with certificates in-memory.

### Embedded

A JSON Web Key (or token) may embed its own certificates. Those certificates must be base64 (not URL)
encoded, and are usually stored in a `x5c` field.

```go
certs, err := jw509.DecodeEmbedded(rawCerts)
```

To generate an embedded chain for your own use, you can use the `EncodeEmbedded` method:

```go
rawCerts := jw509.EncodeEmbedded(certs)
```

### URL

To save space, a token may reference a URL where its certificates are stored. The URL must serve
a chain of PEM-encoded certificates, concatenated into a single bytes array.

```go
req, err := http.NewRequest(http.MethodGet, url, nil)
certs, err := jw509.DecodeURL(url)
```

The decoder takes a `*http.Request` as argument, letting you customize the request as you see fit.

If you wish to serve your own certificates over HTTP, you can use the `EncodeURL` method, to convert
them to the appropriate format.

```go
raw := jw509.EncodeURL(certs)

func ServeCerts(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
```

### Files

The files Encoder/Decoder lets you work with certificates directly in-memory (for example loaded from 
local files).

```go
// Be careful when loading a certificate chain from a local source, as the order of the certificates
// in the chain matters.
var fileNames := []string{
	"path/to/cert1.pem",
	"path/to/cert2.pem",
}

var files [][]byte

for _, fileName := range fileNames {
	file, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	files = append(files, file)
}

certs, err := jw509.DecodeFiles(...files)
```

Similarly, you can use the `EncodeFiles` method to encode the certificates as bytes, that can be saved
to your local filesystem.

```go
files, err := jw509.EncodeFiles(certs)

for i, file := range files {
	err := os.WriteFile(fmt.Sprintf("path/to/cert-%d.pem", i), file, 0644)
	if err != nil {
		return err
	}
}
```

## Match

Match checks the semantic of 2 certificate chains, to ensure they are equivalent.
This is useful when a JSON Web embeds multiple certificates sources (for example embedded and remote).
In those case, JWA requires all representations to match.

```go
// It returns jw509.ErrCertsMismatch if the certificates do not semantically equal.
err := jw509.Match(certs1, certs2)
```

## Match Key

Similarly to [Match](#match), the certificates passed to a JWA must match the public key to be used
with the payload (for signing or encryption).

```go
// Key MUST be a public key.
// It returns jw509.ErrKeyMismatch if the key does not match the certificates.
err := jw509.MatchKey(key, certs)
```

## Thumbprint

To prevent tampering with certificates, JWA provides options to pass Thumbprints, to ensure the
data integrity of the certificates.

You can use the `MatchThumbprint` method to validate those. The thumbprint must be either 20 bytes 
long (for sha1) or 32 bytes long (for sha256).

```go
// It returns jw509.ErrThumbprintMismatch if the thumbprints do not match.
err := jw509.MatchThumbprint(certs, thumbprint)
```

## Validate

While certificates are used to ensure the integrity of a key, it is also useful to ensure the
integrity of the certificates themselves. 

While the `MatchThumbprint` does that partially, it only does so on the first certificate of the chain.
`Validate` provides a (complementary) deeper check, that validates the entire chain.

Unlike other methods, it also requires that you pass a configuration object.

```go
err := jw509.Validate(certs, &jw509.ValidateConfig{})
```

### Validate options

While an empty config works, it is recommended to provide some extra constraints when checking
the certificates.

```go
err := jw509.Validate(certs, &jw509.ValidateConfig{
	// Restrict the trusted origins of the certificates.
	TrustedHostnames: []string{"example.com"},
})
```

You can have a look at the complete options from the struct documentation directly.
