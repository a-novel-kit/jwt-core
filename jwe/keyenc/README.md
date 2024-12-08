# Key encryption

```go
import "github.com/a-novel-kit/jwt-core/jwe/keyenc"
```

Handlers for the key encryption of JSON Web Encryption.

- [Decrypt](#decrypt)
- [Encrypt](#encrypt)
- [Deprecation on RSA1_5 algorithms](#deprecation-on-rsa1_5-algorithms)

## Decrypt

Decrypt takes an encrypted content encryption key (CEK) and a private asymmetric key, and returns the decrypted CEK.

```go
cek, err := keyenc.Decrypt(encryptedKey, privateKey)
```

The following algorithms are supported:

| Algorithm                 | Method                                                                                        |
|---------------------------|-----------------------------------------------------------------------------------------------|
| RSA1_5 ⚠️                 | `DecryptRSAESPKCS1V15(key *rsa.PrivateKey, encrypted []byte) ([]byte, error)`                 |
| RSA-OAEP<br/>RSA-OAEP-256 | `DecryptRSAESOAEP(key *rsa.PrivateKey, keyHash hash.Hash, encrypted []byte) ([]byte, error)`  |

## Encrypt

Encrypt takes a content encryption key (CEK) and a public asymmetric key, and returns the encrypted CEK.

```go
encryptedKey, err := keyenc.Encrypt(cek, publicKey)
```

The following algorithms are supported:

| Algorithm                 | Method                                                                                |
|---------------------------|---------------------------------------------------------------------------------------|
| RSA1_5 ⚠️                 | `EncryptRSAESPKCS1V15(key *rsa.PublicKey, cek []byte) ([]byte, error)`                |
| RSA-OAEP<br/>RSA-OAEP-256 | `EncryptRSAESOAEP(key *rsa.PublicKey, keyHash hash.Hash, cek []byte) ([]byte, error)` |


## Deprecation on RSA1_5 algorithms

RSASSA PKCS #1 v1.5 has been [deprecated by the standards](https://www.rfc-editor.org/rfc/rfc8017#section-8), and 
is only included for backwards compatibility.

> Two signature schemes with appendix are specified in this document: RSASSA-PSS and RSASSA-PKCS1-v1_5. Although 
> no attacks are known against RSASSA-PKCS1-v1_5, in the interest of increased robustness, RSASSA-PSS is REQUIRED 
> in new applications. RSASSA-PKCS1-v1_5 is included only for compatibility with existing applications.
