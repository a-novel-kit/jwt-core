# Key agreement

```go
import "github.com/a-novel-kit/jwt-core/jwe/keyagr"
```

Handlers for the key agreement of JSON Web Encryption.

## Derive

Derive takes a private asymmetric key and a public asymmetric key, and returns the derived shared secret.

```go
sharedSecret, err := keyagr.Derive(privateKey, publicKey, out, apu, apv)
```

Out is the algorithm the derived key is expected to be used with. It can be one of the following:

| Algorithm   | Method              |
|-------------|---------------------|
| AES-CBC-128 | `keyarg.AlgA128CBC` |
| AES-CBC-192 | `keyarg.AlgA192CBC` |
| AES-CBC-256 | `keyarg.AlgA256CBC` |
| AES-GCM-128 | `keyarg.AlgA128GCM` |
| AES-GCM-192 | `keyarg.AlgA192GCM` |
| AES-GCM-256 | `keyarg.AlgA256GCM` |
| A128KW      | `keyarg.AlgA128KW`  |
| A192KW      | `keyarg.AlgA192KW`  |
| A256KW      | `keyarg.AlgA256KW`  |
