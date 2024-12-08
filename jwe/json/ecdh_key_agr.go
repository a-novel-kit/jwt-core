package jwejson

import jwkjson "github.com/a-novel-kit/jwt-core/jwk/json"

// ECDHKeyAgrPayload represents the ECDH-ES key agreement algorithm header parameters.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1
type ECDHKeyAgrPayload struct {
	// EPK (Ephemeral Public Key) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.1
	//
	// The "epk" (ephemeral public key) value created by the originator for
	// the use in key agreement algorithms. This key is represented as a
	// JSON Web Key [JWK] public key value. It MUST contain only public key
	// parameters and SHOULD contain only the minimum JWK parameters
	// necessary to represent the key; other JWK parameters included can be
	// checked for consistency and honored, or they can be ignored. This
	// Header Parameter MUST be present and MUST be understood and processed
	// by implementations when these algorithms are used.
	EPK *jwkjson.ECDHPayload `json:"epk"`
	// APU (Agreement PartyUInfo) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2
	//
	// The "apu" (agreement PartyUInfo) value for key agreement algorithms
	// using it (such as "ECDH-ES"), represented as a base64url-encoded
	// string. When used, the PartyUInfo value contains information about
	// the producer. Use of this Header Parameter is OPTIONAL. This Header
	// Parameter MUST be understood and processed by implementations when
	// these algorithms are used.
	APU string `json:"apu,omitempty"`
	// APV (Agreement PartyVInfo) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3
	//
	// The "apv" (agreement PartyVInfo) value for key agreement algorithms
	// using it (such as "ECDH-ES"), represented as a base64url encoded
	// string. When used, the PartyVInfo value contains information about
	// the recipient. Use of this Header Parameter is OPTIONAL. This
	// Header Parameter MUST be understood and processed by implementations
	// when these algorithms are used.
	APV string `json:"apv,omitempty"`
}
