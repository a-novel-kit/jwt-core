package jwejson

// AESGCMKeyEncPayload represents the AES GCM key encryption algorithm header parameters.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1
type AESGCMKeyEncPayload struct {
	// IV (Initialization Vector) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1
	//
	// The "iv" (initialization vector) Header Parameter value is the
	// base64url-encoded representation of the 96-bit IV value used for the
	// key encryption operation. This Header Parameter MUST be present and
	// MUST be understood and processed by implementations when these
	// algorithms are used.
	IV string `json:"iv"`
	// Tag (Authentication Tag) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2
	//
	// The "tag" (authentication tag) Header Parameter value is the
	// base64url-encoded representation of the 128-bit Authentication Tag
	// value resulting from the key encryption operation. This Header
	// Parameter MUST be present and MUST be understood and processed by
	// implementations when these algorithms are used.
	Tag string `json:"tag"`
}
