# x509 JSON

```go
import "github.com/a-novel-kit/jwt-core/x509/json"
```

Handlers for the JSON Web Algorithm representation of certificates.

## Verify

When receiving certificate information in a JSON Web object, it is important to validate its integrity.

```go
certs, err := jw509json.Verify(certs, &jw509json.VerifyConfig{
	ReqFactory: jw509json.RequestFactoryDefault,
})
```

This method returns the decoded list of certificates on success, so they can be used to validate the key.

### Retrieving remote certificates

When serving certificates over HTTP with the x5u member, the RFC specification requires the usage of TLS.
You might also want to add extra security layers, in the form of authentication or custom headers.

Thus, you must provide a `*http.Request` builder for this method to safely retrieve your keys. This
method takes a `jw509json.Payload` as an input, and returns a `*http.Request`.

```go
func MyReqBuilder(payload *jw509json.Payload) (*http.Request, error) {
	req, err := http.NewRequest("GET", payload.X5u, nil)
	if err != nil {
		return nil, err
	}

	// Do stuff with your request
	
	return req, nil
}
```

You can use the default `jw509json.RequestFactoryDefault` for quick configuration, however beware this
does not use any security layer.

### Further validate integrity of the certificate chain

The default `Verify` behavior performs some quick integrity checks (thumbprints validation, and sources
matching). However, the payload itself may lack information (all fields are optional), and even so,
there is no guarantee the source certificate was valid to begin with.

It is recommended to set up extra configuration to validate the certificate chain itself. You can
do so by passing in a configuration for the `jw509.Validate` method.

```go
certs, err := jw509json.Verify(certs, &jw509json.VerifyConfig{
	ReqFactory: jw509json.RequestFactoryDefault,
	ValidateConfig: &jw509.ValidateConfig{
		// Restrict the trusted origins of the certificates.
		TrustedHostnames: []string{"example.com"},
	},
})
```

## Generate

You can create a configuration from your own certificates, so third party can also validate your
certificates.

```go
payload, err := jw509json.Generate(certs, &jw509json.GenerateConfig{
	Embed: true,
	Serve: "https://example.com/certificates",
	Thumbprint: true,
	Thumbprint256: true,
})
```

All members are optional, so you can choose what will appear on the final payload. The payload can
be embedded directly in your JWT.
