package enc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"

	jweutils "github.com/a-novel-kit/jwt-core/jwe/utils"
	"github.com/a-novel-kit/jwt-core/jwk"
)

var (
	ErrCEKMismatch       = errors.New("invalid CEK size: must match the sum of the encryption and MAC key sizes")
	ErrInvalidCipherText = errors.New("invalid ciphertext")
)

// EncryptAESCBC encrypts the payload using AES-CBC with the given parameters. It returns (in order)
// the encrypted payload and the authentication tag.
//
// Additional data is an optional parameter that can be used to pass unencrypted data to the payload.
func EncryptAESCBC(payload, additionalData []byte, key *jwk.AESKeySet) (*AESPayload, error) {
	var hash crypto.Hash
	var encKeyLen, macKeyLen, tLen int

	switch len(key.CEK) {
	case 32:
		// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3
		hash = crypto.SHA256
		encKeyLen = 16
		macKeyLen = 16
		tLen = 16
	case 48:
		// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4
		hash = crypto.SHA384
		encKeyLen = 24
		macKeyLen = 24
		tLen = 24
	case 64:
		// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5
		hash = crypto.SHA512
		encKeyLen = 32
		macKeyLen = 32
		tLen = 32
	default:
		return nil, errors.New("unsupported key size")
	}

	// The secondary keys MAC_KEY and ENC_KEY are generated from the
	// input key K as follows. Each of these two keys is an octet
	// string.
	//
	// - MAC_KEY consists of the initial MAC_KEY_LEN octets of K, in order.
	// - ENC_KEY consists of the final ENC_KEY_LEN octets of K, in order.
	//
	// The number of octets in the input key K MUST be the sum of
	// MAC_KEY_LEN and ENC_KEY_LEN. The values of these parameters are
	// specified by the Authenticated Encryption algorithms in Sections
	// 5.2.3 through 5.2.5. Note that the MAC key comes before the
	// encryption key in the input key K; this is in the opposite order
	// of the algorithm names in the identifier "AES_CBC_HMAC_SHA2".
	encKey := key.CEK[encKeyLen:]
	macKey := key.CEK[:macKeyLen]

	if len(encKey)+len(macKey) != len(key.CEK) {
		return nil, ErrCEKMismatch
	}

	// The IV used is a 128-bit value generated randomly or
	// pseudorandomly for use in the cipher.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	// The plaintext is CBC encrypted using PKCS #7 padding using
	// ENC_KEY as the key and the IV.
	origData := jweutils.PKCS7Padding(payload, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key.IV)

	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)

	// The octet string AL is equal to the number of bits in the
	// Additional Authenticated Data A expressed as a 64-bit unsigned
	// big-endian integer.
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(additionalData)*8))

	// A message Authentication Tag T is computed by applying HMAC
	// [RFC2104] to the following data, in order:
	//
	// - the Additional Authenticated Data A,
	// - the Initialization Vector IV,
	// - the ciphertext E computed in the previous step, and
	// - the octet string AL defined above.
	//
	// The string MAC_KEY is used as the MAC key. We denote the output
	// of the MAC computed in this step as M. The first T_LEN octets of
	// M are used as T.
	mac := hmac.New(hash.New, macKey)
	mac.Write(additionalData)
	mac.Write(key.IV)
	mac.Write(crypted)
	mac.Write(al)

	// The ciphertext E and the Authentication Tag T are returned as the
	// outputs of the authenticated encryption.
	return &AESPayload{
		E: crypted,
		T: mac.Sum(nil)[:tLen],
	}, nil
}

// DecryptAESCBC decrypts the payload using AES-CBC with the given parameters. It returns the decrypted payload.
func DecryptAESCBC(data *AESPayload, additionalData []byte, key *jwk.AESKeySet) ([]byte, error) {
	var hash crypto.Hash
	var encKeyLen, macKeyLen, tLen int

	switch len(key.CEK) {
	case 32:
		// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3
		hash = crypto.SHA256
		encKeyLen = 16
		macKeyLen = 16
		tLen = 16
	case 48:
		// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4
		hash = crypto.SHA384
		encKeyLen = 24
		macKeyLen = 24
		tLen = 24
	case 64:
		// https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5
		hash = crypto.SHA512
		encKeyLen = 32
		macKeyLen = 32
		tLen = 32
	default:
		return nil, errors.New("unsupported key size")
	}

	// The secondary keys MAC_KEY and ENC_KEY are generated from the
	// input key K as follows. Each of these two keys is an octet
	// string.
	//
	// - MAC_KEY consists of the initial MAC_KEY_LEN octets of K, in order.
	// - ENC_KEY consists of the final ENC_KEY_LEN octets of K, in order.
	//
	// The number of octets in the input key K MUST be the sum of
	// MAC_KEY_LEN and ENC_KEY_LEN. The values of these parameters are
	// specified by the Authenticated Encryption algorithms in Sections
	// 5.2.3 through 5.2.5. Note that the MAC key comes before the
	// encryption key in the input key K; this is in the opposite order
	// of the algorithm names in the identifier "AES_CBC_HMAC_SHA2".
	encKey := key.CEK[encKeyLen:]
	macKey := key.CEK[:macKeyLen]

	if len(encKey)+len(macKey) != len(key.CEK) {
		return nil, ErrCEKMismatch
	}

	// The integrity and authenticity of A and E are checked by
	// computing an HMAC with the inputs as in Step 5 of
	// Section 5.2.2.1.
	// The value T, from the previous step, is
	// compared to the first MAC_KEY length bits of the HMAC output.  If
	// those values are identical, then A and E are considered valid,
	// and processing is continued.  Otherwise, all of the data used in
	// the MAC validation are discarded, and the authenticated
	// decryption operation returns an indication that it failed, and
	// the operation halts.  (But see Section 11.5 of [JWE] for security
	// considerations on thwarting timing attacks.)
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(additionalData)*8))

	mac := hmac.New(hash.New, macKey)
	mac.Write(additionalData)
	mac.Write(key.IV)
	mac.Write(data.E)
	mac.Write(al)

	expect := mac.Sum(nil)[:tLen]
	if !hmac.Equal(data.T, expect) {
		return nil, fmt.Errorf("%w: auth tag check failed", ErrInvalidCipherText)
	}

	// The value E is decrypted and the PKCS #7 padding is checked and
	// removed. The value IV is used as the Initialization Vector. The
	// value ENC_KEY is used as the decryption key.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	blockMode := cipher.NewCBCDecrypter(block, key.IV)
	origData := make([]byte, len(data.E))
	blockMode.CryptBlocks(origData, data.E)

	return jweutils.PKCS7UnPadding(origData), nil
}
