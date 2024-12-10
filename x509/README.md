# x509

```go
import "github.com/a-novel-kit/jwt-core/x509"
```

Manage certificates using x509 package.

- [Thumbprint](#thumbprint)
- [Validate](#validate)
    - [Validate options](#validate-options)

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
