package keyagr

import (
	"crypto"
	"encoding/binary"
	"errors"

	"github.com/a-novel-kit/jwt-core/jwa"
	jweutils "github.com/a-novel-kit/jwt-core/jwe/utils"
	jwkgen "github.com/a-novel-kit/jwt-core/jwk/gen"
)

var ErrKeyMismatch = errors.New("key mismatch")

type AlgType int

const (
	// AlgTypeDirect is the direct key agreement mode.
	AlgTypeDirect AlgType = iota
	// AlgTypeKeyWrap is the key agreement with key wrapping mode.
	AlgTypeKeyWrap
)

// Alg represents the expected output of the key agreement algorithm.
type Alg struct {
	// ID is the algorithm identifier (the "enc" header parameter for direct key agreement, or the "alg" header
	// that should be used for wrapping).
	ID string
	// Size is the expected output size in bytes.
	Size int
	// Type is the type of key agreement algorithm this value should be used with.
	Type AlgType
}

// Direct Key Agreement mode.
var (
	// AlgA128CBC is the algorithm used for direct key agreement with AES-CBC-128.
	AlgA128CBC = Alg{
		ID:   string(jwa.A128CBC),
		Size: int(jwkgen.AESKeySize256),
		Type: AlgTypeDirect,
	}
	// AlgA192CBC is the algorithm used for direct key agreement with AES-CBC-192.
	AlgA192CBC = Alg{
		ID:   string(jwa.A192CBC),
		Size: int(jwkgen.AESKeySize384),
		Type: AlgTypeDirect,
	}
	// AlgA256CBC is the algorithm used for direct key agreement with AES-CBC-256.
	AlgA256CBC = Alg{
		ID:   string(jwa.A256CBC),
		Size: int(jwkgen.AESKeySize512),
		Type: AlgTypeDirect,
	}

	// AlgA128GCM is the algorithm used for direct key agreement with AES-GCM-128.
	AlgA128GCM = Alg{
		ID:   string(jwa.A128GCM),
		Size: int(jwkgen.AESKeySize128),
		Type: AlgTypeDirect,
	}
	// AlgA192GCM is the algorithm used for direct key agreement with AES-GCM-192.
	AlgA192GCM = Alg{
		ID:   string(jwa.A192GCM),
		Size: int(jwkgen.AESKeySize192),
		Type: AlgTypeDirect,
	}
	// AlgA256GCM is the algorithm used for direct key agreement with AES-GCM-256.
	AlgA256GCM = Alg{
		ID:   string(jwa.A256GCM),
		Size: int(jwkgen.AESKeySize256),
		Type: AlgTypeDirect,
	}
)

// KeyWrap Key Agreement mode.
var (
	// AlgA128KW is the algorithm used for key agreement with key wrapping with ECDH-ES+A128KW.
	AlgA128KW = Alg{
		ID:   string(jwa.A128KW),
		Size: int(jwkgen.AESKeySize128),
		Type: AlgTypeKeyWrap,
	}
	// AlgA192KW is the algorithm used for key agreement with key wrapping with ECDH-ES+A192KW.
	AlgA192KW = Alg{
		ID:   string(jwa.A192KW),
		Size: int(jwkgen.AESKeySize192),
		Type: AlgTypeKeyWrap,
	}
	// AlgA256KW is the algorithm used for key agreement with key wrapping with ECDH-ES+A256KW.
	AlgA256KW = Alg{
		ID:   string(jwa.A256KW),
		Size: int(jwkgen.AESKeySize256),
		Type: AlgTypeKeyWrap,
	}
)

// Derive is a generic function to derive a key from a shared secret.
//
// Private key is used to derive the shared secret Z, along with the shared public key.
//
// On the recipient side, it is the private counterpart of the public key shared to the issuer.
//
// On the issuer side, it is an ephemeral key that can be thrown away after the key has been derived (note that
// the public key counterpart must be saved and shared with the recipient).
//
// Alg is the expected algorithm the output key is intended to be used with. This information can be retrieved
// from the "alg" header on the recipient side.
//
// It returns the generated CEK, along with the public counterpart of the ephemeral key used to generate it.
//
// The returned public key can (and must) safely be shared with the recipient, so it can derive the same key.
func Derive(z []byte, out Alg, apu, apv []byte) ([]byte, error) {
	// This is set to the number of bits in the desired output key. For
	// "ECDH-ES", this is length of the key used by the "enc" algorithm.
	// For "ECDH-ES+A128KW", "ECDH-ES+A192KW", and "ECDH-ES+A256KW", this
	// is 128, 192, and 256, respectively.
	keyDataLen := out.Size

	// The AlgorithmID value is of the form Datalen || Data, where Data
	// is a variable-length string of zero or more octets, and Datalen is
	// a fixed-length, big-endian 32-bit counter that indicates the
	// length (in octets) of Data. In the Direct Key Agreement case,
	// Data is set to the octets of the ASCII representation of the "enc"
	// Header Parameter value. In the Key Agreement with Key Wrapping
	// case, Data is set to the octets of the ASCII representation of the
	// "alg" (algorithm) Header Parameter value.
	algID := lengthPrefixed([]byte(out.ID))

	// The PartyUInfo value is of the form Datalen || Data, where Data is
	// a variable-length string of zero or more octets, and Datalen is a
	// fixed-length, big-endian 32-bit counter that indicates the length
	// (in octets) of Data. If an "apu" (agreement PartyUInfo) Header
	// Parameter is present, Data is set to the result of base64url
	// decoding the "apu" value and Datalen is set to the number of
	// octets in Data. Otherwise, Datalen is set to 0 and Data is set to
	// the empty octet sequence.
	ptyUInfo := lengthPrefixed(apu)

	// The PartyVInfo value is of the form Datalen || Data, where Data is
	// a variable-length string of zero or more octets, and Datalen is a
	// fixed-length, big-endian 32-bit counter that indicates the length
	// (in octets) of Data. If an "apv" (agreement PartyVInfo) Header
	// Parameter is present, Data is set to the result of base64url
	// decoding the "apv" value and Datalen is set to the number of
	// octets in Data. Otherwise, Datalen is set to 0 and Data is set to
	// the empty octet sequence.
	ptyVInfo := lengthPrefixed(apv)

	// This is set to the keydatalen represented as a 32-bit big-endian integer.
	supPubInfo := make([]byte, 4)
	if keyDataLen > 0xFFFFFFF {
		return nil, errors.New("keyDataLen is too large")
	}

	binary.BigEndian.PutUint32(supPubInfo, uint32(keyDataLen)*8)

	// This is set to the empty octet sequence.
	var supPrivInfo []byte

	// Derive the shared key.
	return jweutils.ConcatKDF(crypto.SHA256, z, keyDataLen, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo), nil
}

// lengthPrefixed prefixes the input data with a 32-bit big-endian length.
func lengthPrefixed(data []byte) []byte {
	out := make([]byte, len(data)+4)
	if len(data) > 0xFFFFFFF {
		panic("data is too large")
	}

	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}
