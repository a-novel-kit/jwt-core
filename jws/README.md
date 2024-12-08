# JWS

```go
import "github.com/a-novel-kit/jwt-core/jws"
```

Signature algorithms for JWT.

- [Verify](#verify)
- [Sign](#sign)
- [Deprecation on RSA1_5 algorithms](#deprecation-on-rsa1_5-algorithms)

## Verify

Verification algorithms take an unsigned payload and a signature, both base64 url-encoded, along with public key
data. It ensures the signature is valid for the payload, using the provided public key.

```go
ok, err := jws.Verify(payload, signature, publicKey)
```

If the payload cannot be validated by the signature, `jws.ErrInvalidSignature` is always returned.

The following algorithms are supported:

| Algorithm            | Method                                                                                        |
|----------------------|-----------------------------------------------------------------------------------------------|
| HMAC with SHA-2      | `VerifyHMAC(unsigned string, signature string, key []byte, hash crypto.Hash) error`           |
| RSASSA-PKCS1-v1_5 ⚠️ | `VerifyRSA(unsigned string, signature string, key *rsa.PublicKey, hash crypto.Hash) error`    |
| ECDSA                | `VerifyEC(unsigned string, signature string, key *ecdsa.PublicKey) error`                     |
| RSASSA-PSS           | `VerifyRSAPSS(unsigned string, signature string, key *rsa.PublicKey, hash crypto.Hash) error` |
| EdDSA (x25519)       | `VerifyED25519(unsigned string, signature string, key *ed25519.PublicKey) error`              |

## Sign

Signature algorithms take an unsigned payload and a private key, and return a base64 url-encoded signature.

```go
signature, err := jws.Sign(payload, privateKey)
```

The following algorithms are supported:

| Algorithm            | Method                                                                               |
|----------------------|--------------------------------------------------------------------------------------|
| HMAC with SHA-2      | `SignHMAC(unsigned string, key []byte, hash crypto.Hash) (string, error)`            |
| RSASSA-PKCS1-v1_5 ⚠️ | `SignRSA(unsigned string, key *rsa.PrivateKey, hash crypto.Hash) (string, error)`    |
| ECDSA                | `SignEC(unsigned string, key *ecdsa.PrivateKey) (string, error)`                     |
| RSASSA-PSS           | `SignRSAPSS(unsigned string, key *rsa.PrivateKey, hash crypto.Hash) (string, error)` |
| EdDSA (x255219)      | `SignED25519(unsigned string, key *ed25519.PrivateKey) string`                       |

## Deprecation on RSA1_5 algorithms

RSASSA PKCS #1 v1.5 has been [deprecated by the standards](https://www.rfc-editor.org/rfc/rfc8017#section-8), and
is only included for backwards compatibility.

> Two signature schemes with appendix are specified in this document: RSASSA-PSS and RSASSA-PKCS1-v1_5. Although
> no attacks are known against RSASSA-PKCS1-v1_5, in the interest of increased robustness, RSASSA-PSS is REQUIRED
> in new applications. RSASSA-PKCS1-v1_5 is included only for compatibility with existing applications.
