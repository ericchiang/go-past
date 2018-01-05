// Package past implements the Platform-Agnostic Security Tokens specification.
//
//		key, err := past.NewKey()
//		if err != nil {
//			// handle error
//		}
//		data := `{"data":"this is an authenticated message","exp":"2039-01-01T00:00:00"}`
//		token, err := past.V2.Auth(key, data)
//
package past

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

var enc = base64.RawURLEncoding

type version2 struct{}

var (
	// V1 implements the following algorithms:
	// - auth: HMAC-SHA384
	// - enc:  AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC) with HKDF-SHA384
	// - sign: *not implemented* (RSASSA-PSS)
	V1 = Version{version1{}}
	// V2 implements the following algorithms:
	// - auth: HMAC-SHA512
	// - enc:  *not implemented* (XChaCha20-Poly1305)
	// - sign: ED25519
	V2 = Version{version2{}}
)

const (
	tokenTypeV1Auth = "v1.auth."
	tokenTypeV1Enc  = "v1.enc."
	tokenTypeV1Sign = "v1.sign."
	tokenTypeV2Auth = "v2.auth."
	tokenTypeV2Sign = "v2.sign."
	tokenTypeV2Enc  = "v2.enc."
)

// Version is a PAST version. The version determines the authentication, encryption
// and signing algorithms used to creating tokens.
type Version struct {
	v version
}

// Auth creates an authenticated token from the key and payload.
func (v *Version) Auth(key, payload []byte) (string, error) {
	return v.v.Auth(key, payload)
}

// AuthVerify verifies the token's authentication tag and returns the payload.
func (v *Version) AuthVerify(key []byte, token string) ([]byte, error) {
	return v.v.AuthVerify(key, token)
}

// Enc returns a token that encrypts and authenticates the payload.
func (v *Version) Enc(key, payload []byte) (string, error) {
	return v.v.Enc(key, payload)
}

// EncVerify decrypts and authenticates a token and returns the payload.
func (v *Version) EncVerify(key []byte, token string) ([]byte, error) {
	return v.v.EncVerify(key, token)
}

// Sign creates a signed token from the key and payload.
func (v *Version) Sign(key crypto.Signer, payload []byte) (string, error) {
	return v.v.Sign(key, payload)
}

// SignVerify verifies the token's signature and returns the paylaod.
func (v *Version) SignVerify(key crypto.PublicKey, token string) ([]byte, error) {
	return v.v.SignVerify(key, token)
}

type version interface {
	// Auth creates an authenticated token from the key and payload.
	Auth(key, payload []byte) (string, error)
	// AuthVerify verifies the token's authentication tag and returns the payload.
	AuthVerify(key []byte, token string) ([]byte, error)

	// Enc returns a token that encrypts and authenticates the payload.
	Enc(key, payload []byte) (string, error)
	// EncVerify decrypts and verifies the authentication tag of a token and returns
	// the payload.
	EncVerify(key []byte, token string) ([]byte, error)

	// Sign creates a signed token from the key and payload.
	Sign(key crypto.Signer, payload []byte) (string, error)
	// SignVerify verifies the token's signature and returns the paylaod.
	SignVerify(key crypto.PublicKey, token string) ([]byte, error)
}

func parseToken(token, tokenType string, tagLen int) (payload, tag []byte, ok bool) {
	if !strings.HasPrefix(token, tokenType) {
		return nil, nil, false
	}
	data, err := enc.DecodeString(token[len(tokenType):])
	if err != nil {
		return nil, nil, false
	}
	if len(data) < tagLen {
		return nil, nil, false
	}
	return data[:len(data)-tagLen], data[len(data)-tagLen:], true
}

func (v version2) NewEncKey() ([]byte, error) {
	return nil, errors.New("past: v2 encryption not supported")
}

func (v version2) Enc(key, payload []byte) (string, error) {
	return "", errors.New("past: v2 encryption not supported")
}

func (v version2) EncVerify(key []byte, token string) ([]byte, error) {
	return nil, errors.New("past: v2 encryption not supported")
}

// NewV2SignKey returns a signing key used for V1 signatures.
func NewV1SignKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// NewV2SignKey returns a signing key used for V2 signatures.
func NewV2SignKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// NewKey returns a symmetric key for authentication and/or encryption.
func NewKey() ([]byte, error) {
	return newRandBytes(32)
}

func (v version2) Sign(key crypto.Signer, payload []byte) (string, error) {
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("past: v2 unsupported private key")
	}

	sig := ed25519.Sign(priv, pae(tokenTypeV2Sign, string(payload), ""))
	data := make([]byte, len(payload)+len(sig))
	copy(data, payload)
	copy(data[len(payload):], sig)

	return tokenTypeV2Sign + enc.EncodeToString(data), nil
}

func (v version2) SignVerify(key crypto.PublicKey, token string) ([]byte, error) {
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("past: v2 unsupported public key")
	}

	payload, tag, ok := parseToken(token, tokenTypeV2Sign, ed25519.SignatureSize)
	if !ok {
		return nil, errors.New("past: malformed signed token")
	}

	if !ed25519.Verify(pub, pae(tokenTypeV2Sign, string(payload), ""), tag) {
		return nil, errors.New("past: invalid token signature")
	}
	return payload, nil
}

func newRandBytes(n int) ([]byte, error) {
	key := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

const v2MacLength = 32

func computeV2Mac(key, payload, footer []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(pae(tokenTypeV2Auth, string(payload), string(footer)))
	return h.Sum(nil)[:v2MacLength]
}

func (v version2) Auth(key, payload []byte) (string, error) {
	mac := computeV2Mac(key, payload, []byte{})

	data := make([]byte, len(payload)+len(mac))
	copy(data, payload)
	copy(data[len(payload):], mac)

	return tokenTypeV2Auth + enc.EncodeToString(data), nil
}

func (v version2) AuthVerify(key []byte, token string) ([]byte, error) {
	payload, tag, ok := parseToken(token, tokenTypeV2Auth, v2MacLength)
	if !ok {
		return nil, errors.New("past: malformed authenticated token")
	}

	if !hmac.Equal(tag, computeV2Mac(key, payload, []byte{})) {
		return nil, errors.New("past: invalid token authentication tag")
	}
	return payload, nil
}

type version1 struct{}

func (v version1) Enc(key, payload []byte) (string, error) {
	nonce, err := newRandBytes(32)
	if err != nil {
		return "", err
	}
	encKey, authKey, err := split(key, nonce[:16])
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	cipherText := make([]byte, len(payload))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(cipherText, payload)

	h := hmac.New(sha512.New384, authKey)
	h.Write(pae(tokenTypeV1Enc, string(nonce), string(cipherText), ""))
	mac := h.Sum(nil)

	data := append(nonce, cipherText...)
	data = append(data, mac...)

	return tokenTypeV1Enc + enc.EncodeToString(data), nil
}

func (v version1) EncVerify(key []byte, token string) ([]byte, error) {
	payload, tag, ok := parseToken(token, tokenTypeV1Enc, sha512.Size384)
	if !ok || len(payload) < 32 {
		return nil, errors.New("past: malformed encrypted token")
	}

	nonce, cipherText := payload[:32], payload[32:]

	encKey, authKey, err := split(key, nonce[:16])
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha512.New384, authKey)
	h.Write(pae(tokenTypeV1Enc, string(nonce), string(cipherText), ""))
	if !hmac.Equal(h.Sum(nil), tag) {
		return nil, errors.New("past: invalid token authentication tag")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(cipherText))
	cipher.NewCTR(block, nonce[16:]).XORKeyStream(plainText, cipherText)

	return plainText, nil
}

func (v version1) Sign(key crypto.Signer, payload []byte) (string, error) {
	return "", errors.New("past: v1 signing not implemented")
}

func (v version1) SignVerify(key crypto.PublicKey, token string) ([]byte, error) {
	return nil, nil
}

func computeV1Mac(key, payload, footer []byte) []byte {
	h := hmac.New(sha512.New384, key)
	h.Write(pae(tokenTypeV1Auth, string(payload), string(footer)))
	return h.Sum(nil)
}

func (v version1) NewAuthKey() ([]byte, error) { return newRandBytes(256) }

func (v version1) Auth(key, payload []byte) (string, error) {
	mac := computeV1Mac(key, payload, []byte{}) // TODO: Support footer

	data := make([]byte, len(payload)+len(mac))
	copy(data, payload)
	copy(data[len(payload):], mac)

	return tokenTypeV1Auth + enc.EncodeToString(data), nil
}

func (v version1) AuthVerify(key []byte, token string) ([]byte, error) {
	payload, tag, ok := parseToken(token, tokenTypeV1Auth, sha512.Size384)
	if !ok {
		return nil, errors.New("past: malformed authenticated token")
	}

	if !hmac.Equal(tag, computeV1Mac(key, payload, []byte{})) {
		return nil, errors.New("past: invalid token authentication tag")
	}
	return payload, nil
}

// pae computes the pre auth encoding as described in:
//
// https://github.com/paragonie/past/blob/v0.2.0/docs/01-Protocol-Versions/Common.md
func pae(sli ...string) []byte {
	s := le64(len(sli))
	for _, ele := range sli {
		s += le64(len(ele))
		s += ele
	}
	return []byte(s)
}

func le64(n int) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(n))
	s := strconv.QuoteToASCII(string(b[:]))
	s = s[1:]
	s = s[:len(s)-1]
	return s
}

// split splits 32 byte key and a 16 byte nonce into two 32 byte keys using HKDF.
// This is ported directly from the PHP source code:
//
// https://github.com/paragonie/past/blob/v0.2.0/src/Keys/SymmetricEncryptionKey.php#L80
func split(key, nonce []byte) (encKey, authKey []byte, err error) {
	eReader := hkdf.New(sha512.New384, key, nonce[:], []byte("past-encryption-key"))
	aReader := hkdf.New(sha512.New384, key, nonce[:], []byte("past-auth-key-for-aead"))
	encKey = make([]byte, 32)
	authKey = make([]byte, 32)
	if _, err = io.ReadFull(eReader, encKey); err != nil {
		return nil, nil, err
	}
	if _, err = io.ReadFull(aReader, authKey); err != nil {
		return nil, nil, err
	}
	return
}
