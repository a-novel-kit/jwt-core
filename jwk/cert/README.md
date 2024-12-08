# Key certificates

```go
import "github.com/a-novel-kit/jwt-core/jwk/cert"
```

Manage secret keys using certificates, when supported.

- [Key certificates](#key-certificates)
  - [How to use](#how-to-use)
    - [Encode](#encode)
    - [Decode](#decode)
  - [Available functions](#available-functions)
    - [RSA](#rsa)
    - [ECDSA](#ecdsa)

## How to use

Each supported key comes with 2 methods: an `Encode` and a `Decode`.

> The method in this section are provided as a generic example, but are not exported byy the package.
> You can refer to the [Available functions](#available-functions) section for a list of available
> methods.

### Encode

The encoder takes a private key, and generates a PEM-encoded certificate for it.

```go
cert, err := jwkcert.EncodeKey(privateKey)
```

The certificate is generated in-memory, letting you decide where and how you want to save it.
The simpliest use-case is to save it on your local filesystem.

```go
err := os.WriteFile("path/to/cert.pem", cert, 0644)
```

### Decode

The decoder takes a PEM-encoded certificate, and parses a private key from it.

```go
privateKey, err := jwkcert.DecodeKey(cert)
```

The cert represents the raw file as bytes. A common use-case is to read it from your local filesystem.

```go
cert, err := os.ReadFile("path/to/cert.pem")
```

## Available functions

### RSA

```go
EncodeRSA(key *rsa.PrivateKey) []byte
DecodeRSA(data []byte) (*rsa.PrivateKey, error)
```

### ECDSA

```go
EncodeECDSA(key *ecdsa.PrivateKey) ([]byte, error)
DecodeECDSA(data []byte) (*ecdsa.PrivateKey, error)
```
