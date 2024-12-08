# Content encryption

```go
import "github.com/a-novel-kit/jwt-core/jwe/enc"
```

Handlers for the content encryption of JSON Web Encryption.

- [Decrypt](#decrypt)
- [Encrypt](#encrypt)
- [Keygen](#keygen)

## Decrypt

Decrypt takes JWE claims, and decode them using a symmetric key. It returns the decrypted payload.

```go
rawData, err := enc.Decrypt(claims, additionalData, key)
```

The following algorithms are supported:

| Algorithm | Method                                                                                |
|-----------|---------------------------------------------------------------------------------------|
| AES CBC   | `DecryptAESCBC(data *AESPayload, additionalData []byte, key *AESKey) ([]byte, error)` |
| AES GCM   | `DecryptAESGCM(data *AESPayload, additionalData []byte, key *AESKey) ([]byte, error)` |

## Encrypt

Encrypt takes a payload and a symmetric key, and returns JWE claims.

```go
claims, err := enc.Encrypt(payload, additionalData, key)
```

The returned claims contain the following data:

| Field      | Description             |
|------------|-------------------------|
| `E []byte` | The encrypted message.  |
| `T []byte` | The authentication tag. |

The following algorithms are supported:

| Algorithm | Method                                                                            |
|-----------|-----------------------------------------------------------------------------------|
| AES CBC   | `EncryptAESCBC(payload, additionalData []byte, key *AESKey) (*AESPayload, error)` |
| AES GCM   | `EncryptAESGCM(payload, additionalData []byte, key *AESKey) (*AESPayload, error)` |


## Keygen

AES key must follow strict constraints when generated. This packages provides some helpers to generate
them.

```go
key, err := enc.GenerateKey(symmetric.KeySize)
```

All key generators take a key size as argument, that helps switch between the available key sizes.
It returns a key with 2 fields:

| Field        | Description                 |
|--------------|-----------------------------|
| `CEK []byte` | The content encryption key. |
| `IV []byte`  | The initialization vector.  |

The following algorithms are supported:

| Algorithm | Method                                                   |
|-----------|----------------------------------------------------------|
| AES CBC   | `GenerateAESKey(keySize CBCKeySize) (*AESKey, error)`    |
| AES GCM   | `GenerateAESGCMKey(keySize GCMKeySize) (*AESKey, error)` |
