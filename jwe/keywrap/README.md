# Key wrapping

```go
import "github.com/a-novel-kit/jwt-core/jwe/keywrap"
```
 
Handlers for the key wrapping of JSON Web Encryption.

- [Wrap](#wrap)
- [Unwrap](#unwrap)

## Wrap

Wrap takes a content encryption key (CEK) and a key wrapping key, and returns the wrapped CEK.

```go
wrappedKey, err := keywrap.Wrap(kwk, cek)
```

The following algorithms are supported:

| Algorithm | Method                                     | Key Constraints                                                                         | 
|-----------|--------------------------------------------|-----------------------------------------------------------------------------------------|
| AESKW     | `WrapAES(kwk, cek []byte) ([]byte, error)` | 128 bit KEK for `A128KW`<br/>192 bit KEK for `A192KW`<br/>256 bit KEK for `A256KW`<br/> |

## Unwrap

Unwrap takes a wrapped content encryption key (CEK) and a key unwrapping key, and returns the unwrapped CEK.

```go
cek, err := keywrap.Unwrap(kwk, wrappedKey)
```

The following algorithms are supported:

| Algorithm | Method                                              | Key Constraints                                                                         |
|-----------|-----------------------------------------------------|-----------------------------------------------------------------------------------------|
| AESKW     | `UnwrapAES(kwk, wrappedKey []byte) ([]byte, error)` | 128 bit KEK for `A128KW`<br/>192 bit KEK for `A192KW`<br/>256 bit KEK for `A256KW`<br/> |
