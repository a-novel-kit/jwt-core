package jwejson

// PBES2KeyEncPayload represents the PBES2 key encryption algorithm header parameters.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1
type PBES2KeyEncPayload struct {
	// P2S (PBES2 Salt Input) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1
	//
	// The "p2s" (PBES2 salt input) Header Parameter encodes a Salt Input
	// value, which is used as part of the PBKDF2 salt value. The "p2s"
	// value is BASE64URL(Salt Input). This Header Parameter MUST be
	// present and MUST be understood and processed by implementations when
	// these algorithms are used.
	//
	// The salt expands the possible keys that can be derived from a given
	// password. A Salt Input value containing 8 or more octets MUST be
	// used. A new Salt Input value MUST be generated randomly for every
	// encryption operation; see RFC 4086 [RFC4086] for considerations on
	// generating random values. The salt value used is (UTF8(Alg) || 0x00
	// || Salt Input), where Alg is the "alg" (algorithm) Header Parameter
	// value.
	P2S string `json:"p2s"`
	// P2C (PBES2 Count) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2
	//
	// The "p2c" (PBES2 count) Header Parameter contains the PBKDF2
	// iteration count, represented as a positive JSON integer. This Header
	// Parameter MUST be present and MUST be understood and processed by
	// implementations when these algorithms are used.
	//
	// The iteration count adds computational expense, ideally compounded by
	// the possible range of keys introduced by the salt. A minimum
	// iteration count of 1000 is RECOMMENDED.
	P2C int `json:"p2c"`
}
