# Key JSON

```go
import "github.com/a-novel-kit/jwt-core/jwk/json"
```

Handlers for the JSON Web Algorithm representation of keys.

- [Key JSON](#key-json)
  - [Encode](#encode)
  - [Decode](#decode)

## Encode

The encoder takes a key, and generates a JSON Web Key representation for it.
The key can either be a private key, or a derived public key. The payload definition is usually
shared between both.

```go
payload, err := jwkjson.EncodeKey(key)
```

You can directly use this payload as part of your JWT generation. It supports JSON marshalling.

```go
type JsonKey struct {
	MyCustomField any `json:"my_custom_field"`
	
	// Field will be inlined in the final result.
	*jwkjson.KeyPayload
}

myKey := JsonKey{
	MyCustomField: "foo",
	KeyPayload: payload,
}

encoded, err := json.Marshal(myKey)
```

The following algorithms are supported:

| Algorithm | Key type  | Method                                                                               |
|-----------|-----------|--------------------------------------------------------------------------------------|
| Oct       | Symmetric | `EncodeOct(key []byte) *OctPayload`                                                  |
| RSA       | RSA       | `EncodeRSA[Key *rsa.PublicKey \| *rsa.PrivateKey](key Key) *RSAPayload`              |
| ECDSA     | ECDSA     | `EncodeEC[Key *ecdsa.PublicKey \| *ecdsa.PrivateKey](key Key) (*ECPayload, error)`   |
| EdDSA     | EdDSA     | `EncodeED[Key *ed25519.PublicKey \| *ed25519.PrivateKey](key Key) *EDPayload`        |
| ECDH      | ECDH      | `EncodeECDH[Key *ecdh.PublicKey \| *ecdh.PrivateKey](key Key) (*ECDHPayload, error)` |

## Decode

The decoder takes a JSON Web Key representation, and parses a keypair from it.

```go
privateKey, publicKey, err := jwkjson.DecodeKey(jwk)
```

The decoder always returns a private and a public key (except for symmetric keys). If the payload
represents a public key, then the private key will be nil.

The following algorithms are supported:

| Algorithm | Method                                                                      |
|-----------|-----------------------------------------------------------------------------|
| Oct       | `DecodeOct(src *OctPayload) ([]byte, error)`                                |
| RSA       | `DecodeRSA(src *RSAPayload) (*rsa.PrivateKey, *rsa.PublicKey, error)`       |
| ECDSA     | `DecodeEC(src *ECPayload) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)`     |
| EdDSA     | `DecodeED(src *EDPayload) (*ed25519.PrivateKey, *ed25519.PublicKey, error)` |
| ECDH      | `DecodeECDH(src *ECDHPayload) (*ecdh.PrivateKey, *ecdh.PublicKey, error)`   |
