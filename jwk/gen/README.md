# Keygen

```go
import "github.com/a-novel-kit/jwt-core/jwk/gen"
```

Generate keys compatible with the JWK standards.

- [HMAC](#hmac)
- [RSA](#rsa)
- [ECDSA](#ecdsa)
- [Elliptic-Curve Diffie-Hellman](#elliptic-curve-diffie-hellman)
  - [ED25519](#ed25519)
  - [X25519](#x25519)
- [AES](#aes)
  - [Initialization Vector](#initialization-vector)
  - [Key set](#key-set)

## HMAC

HMAC keys are symmetric keys, consisting of random bytes. They require a key size to be generated.

```go
key, err := jwkgen.GenerateHMACKey(keySize)
```

You can use the recommended key sizes for your algorithm:

| Algorithm | Key Size             |
|-----------|----------------------|
| HS256     | `jwkgen.H256KeySize` |
| HS384     | `jwkgen.H384KeySize` |
| HS512     | `jwkgen.H512KeySize` |

## RSA

RSA keys are asymmetric keys, consisting of a public and a private key. They require a key size to 
be generated.

```go
// You can extract the public key from its private counterpart.
//  pubKey = privateKey.PublicKey
privateKey, err := jwkgen.GenerateRSAKey(keySize)
```

You can use the recommended key sizes for your algorithm:

| Algorithm       | Key Size              |
|-----------------|-----------------------|
| RS256<br/>PS256 | `jwkgen.RS256KeySize` |
| RS384<br/>PS384 | `jwkgen.RS384KeySize` |
| RS512<br/>PS512 | `jwkgen.RS512KeySize` |

## ECDSA

ECDSA keys are asymmetric keys, based on Elliptic Curves. They require a curve to be generated.

```go
// You can extract the public key from its private counterpart.
//  pubKey = privateKey.PublicKey
privateKey, err := jwkgen.GenerateECDSAKey(curve)
```

The following curves are supported:

| Curve | Method            |
|-------|-------------------|
| P256  | `elliptic.P256()` |
| P384  | `elliptic.P384()` |
| P521  | `elliptic.P521()` |

## Elliptic-Curve Diffie-Hellman

This package provides handlers for the X25519 curve, introduced in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc8037).

Those algorithms use separate keys for signing and encryption. Both MUST not be interchanged.

### ED25519

ED25519 keys are asymmetric keys, based on the Ed25519 curve.

```go
privKey, pubKey, err := jwkgen.ED25519()
```

### X25519

X25519 keys are asymmetric keys, based on the X25519 curve.

```go
privKey, pubKey, err := jwkgen.X25519()
```

## AES

AES are symmetric keys used for content encryption. They require a key size to be generated.

```go
key, err := jwkgen.AES(keySize)
```

You can use the recommended key sizes for your algorithm:

| Algorithm | Key Size               |
|-----------|------------------------|
| 128 bit   | `jwkgen.AESKeySize128` |
| 192 bit   | `jwkgen.AESKeySize192` |
| 256 bit   | `jwkgen.AESKeySize256` |
| 384 bit   | `jwkgen.AESKeySize384` |
| 512 bit   | `jwkgen.AESKeySize512` |

### Initialization Vector

Content encryption usually requires an additional initialization vector (IV).

```go
iv, err := jwkgen.IV(keySize)
```

You can use the recommended key sizes for your algorithm:

| Algorithm | Key Size             |
|-----------|----------------------|
| 96 bit    | `jwkgen.IVSize96`    |
| 128 bit   | `jwkgen.IVSize128`   |

### Key set

Since AES encryption key and initialization vector are often used together, you can generate them at once.

```go
key, iv, err := jwkgen.AESKeySet(preset)
```

The following presets are available, for recommended algorithms:

| Algorithm     | Preset                    |
|---------------|---------------------------|
| A128CBC-HS256 | `jwkgen.A128CBCKeyPreset` |
| A192CBC-HS384 | `jwkgen.A192CBCKeyPreset` |
| A256CBC-HS512 | `jwkgen.A256CBCKeyPreset` |
| A128GCM       | `jwkgen.A128GCMKeyPreset` |
| A192GCM       | `jwkgen.A192GCMKeyPreset` |
| A256GCM       | `jwkgen.A256GCMKeyPreset` |
