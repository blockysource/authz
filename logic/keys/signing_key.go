// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"reflect"

	"github.com/blockysource/authz/types/algorithm"
	localtypes "github.com/blockysource/authz/types/local"
	"github.com/blockysource/go-genproto/blocky/authz/type/jwkpb"
)

// ErrUnsupportedKeyType is returned when the key type is not supported.
var ErrUnsupportedKeyType = errors.New("unsupported RSA key type")

// SigningKey is a key used for signing tokens.
type SigningKey struct {
	// KeyID is the unique identifier of the key.
	KeyID string

	// CoreID is the identifier of the core that this key was derived from.
	CoreID string

	// Priority is the priority of the key.
	Priority int

	// Algorithm is the signing algorithm associated with the key.
	Algorithm algorithm.SigningAlgorithm

	// Key is the signing key raw value, depending on the algorithm type it can be:
	// - []byte for HMAC
	// - *rsa.PrivateKey for RSA
	// - *ecdsa.PrivateKey for ECDSA
	// - ed25519.PrivateKey for EdDSA
	Key crypto.PrivateKey

	Certificates                []*x509.Certificate
	CertificatesURL             *url.URL
	CertificateThumbprintSHA1   []byte
	CertificateThumbprintSHA256 []byte
}

// NewSigningKey creates a new signing key from the types.KeyRevisionSecret.
func NewSigningKey(key localtypes.Key) (*SigningKey, error) {
	sk := SigningKey{
		CoreID:    key.CoreID,
		Priority:  key.Priority,
		Algorithm: key.Algorithm,
		KeyID:     key.KeyID,
	}

	pk, err := key.ParsePrivateKey()
	if err != nil {
		return nil, err
	}

	sk.Key = pk

	return &sk, nil
}

// NewNoneSigningKey creates a new signing key with the None algorithm.
func NewNoneSigningKey() *SigningKey {
	return &SigningKey{Algorithm: algorithm.SigningAlgorithmNone}
}

// SignData signs the data using the signing key.
func (k *SigningKey) SignData(data []byte) ([]byte, error) {
	if k.Algorithm == algorithm.SigningAlgorithmNone {
		return nil, nil
	}

	switch key := k.Key.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(key, data), nil
	case *ecdsa.PrivateKey:
		return k.signEcdsaData(data, key)
	case *rsa.PrivateKey:
		return k.signRsaData(data, key)
	case []byte:
		return k.signHmacData(data, key)
	default:
		return nil, fmt.Errorf("unknown key type '%s'", reflect.TypeOf(key))
	}
}

func (k *SigningKey) signEcdsaData(data []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	var (
		ch crypto.Hash
		ks int
	)
	switch k.Algorithm {
	case algorithm.SigningAlgorithmES256:
		ch = crypto.SHA256
		ks = 32
	case algorithm.SigningAlgorithmES384:
		ch = crypto.SHA384
		ks = 48
	case algorithm.SigningAlgorithmES512:
		ch = crypto.SHA512
		ks = 64
	default:
		return nil, fmt.Errorf("unknown algorithm '%s' for ecdsa algorithm", k.Algorithm)
	}

	h := ch.New()
	h.Write(data)
	hashed := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
	if err != nil {
		return nil, err
	}

	sig := make([]byte, 2*ks)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[ks-len(rb):ks], rb)
	copy(sig[2*ks-len(sb):], sb)

	return sig, nil
}

// VerificationKey returns a verification key representation of the signing key.
func (k *SigningKey) VerificationKey() *VerificationKey {
	var pk crypto.PublicKey
	switch kt := k.Key.(type) {
	case ed25519.PrivateKey:
		pk = kt.Public()
	case *ecdsa.PrivateKey:
		pk = kt.Public()
	case *rsa.PrivateKey:
		pk = kt.Public()
	case []byte:
		pk = kt
	}
	return &VerificationKey{
		ID:                          k.KeyID,
		Key:                         pk,
		Algorithm:                   k.Algorithm,
		Certificates:                k.Certificates,
		CertificatesURL:             k.CertificatesURL,
		CertificateThumbprintSHA1:   k.CertificateThumbprintSHA1,
		CertificateThumbprintSHA256: k.CertificateThumbprintSHA256,
	}
}

// MarshalBinary marshals the signing key to PKCS#8 format.
func (k *SigningKey) MarshalBinary() ([]byte, error) {
	if kb, ok := k.Key.([]byte); ok {
		return kb, nil
	}

	return x509.MarshalPKCS8PrivateKey(k.Key)
}

// SetProto returns a protobuf JSON Web Key representation of the verification key.
func (k *SigningKey) SetProto(jwk *jwkpb.JWK) error {
	// Reset the input jwk to a blank state.
	jwk.Reset()

	var err error
	switch key := k.Key.(type) {
	case ed25519.PrivateKey:
		fromEdPrivateKey(key, jwk)
	case *ecdsa.PrivateKey:
		err = fromEcPrivateKey(key, jwk)
	case *rsa.PrivateKey:
		err = fromRsaPrivateKey(key, jwk)
	case []byte:
		fromSymmetricKey(key, jwk)
	default:
		return fmt.Errorf("unknown key type '%s'", reflect.TypeOf(key))
	}

	if err != nil {
		return err
	}

	jwk.Kid = k.KeyID
	jwk.Alg = k.Algorithm.String()
	jwk.Use = "sig"

	for _, cert := range k.Certificates {
		jwk.X5C = append(jwk.X5C, cert.Raw)
	}

	x5tSHA1Len := len(k.CertificateThumbprintSHA1)
	x5tSHA256Len := len(k.CertificateThumbprintSHA256)
	if x5tSHA1Len > 0 {
		if x5tSHA1Len != sha1.Size {
			return fmt.Errorf("invalid SHA-1 thumbprint (must be %d bytes, not %d)", sha1.Size, x5tSHA1Len)
		}
		jwk.X5TSha1 = k.CertificateThumbprintSHA1
	}
	if x5tSHA256Len > 0 {
		if x5tSHA256Len != sha256.Size {
			return fmt.Errorf("invalid SHA-256 thumbprint (must be %d bytes, not %d)", sha256.Size, x5tSHA256Len)
		}
		jwk.X5TSha256 = k.CertificateThumbprintSHA256
	}

	// If cert chain is attached (as opposed to being behind a URL), check the
	// keys thumbprints to make sure they match what is expected. This is to
	// ensure we don't accidentally produce a JWK with semantically inconsistent
	// data in the headers.
	if len(k.Certificates) > 0 {
		expectedSHA1 := sha1.Sum(k.Certificates[0].Raw)
		expectedSHA256 := sha256.Sum256(k.Certificates[0].Raw)

		if len(k.CertificateThumbprintSHA1) > 0 && !bytes.Equal(k.CertificateThumbprintSHA1, expectedSHA1[:]) {
			return errors.New("invalid SHA-1 thumbprint, does not match cert chain")
		}
		if len(k.CertificateThumbprintSHA256) > 0 && !bytes.Equal(k.CertificateThumbprintSHA256, expectedSHA256[:]) {
			return errors.New("invalid or SHA-256 thumbprint, does not match cert chain")
		}
	}

	if k.CertificatesURL != nil {
		jwk.X5U = k.CertificatesURL.String()
	}

	return nil
}

// FromProto parses a JWK from the jwkpb.JWK format.
func (k *SigningKey) FromProto(raw *jwkpb.JWK) (err error) {
	certs, err := parseCertificateChain(raw.X5C)
	if err != nil {
		return fmt.Errorf("failed to unmarshal x5c field: %s", err)
	}

	var key any
	var certPub any
	var keyPub any

	if len(certs) > 0 {
		// We need to check that leaf public key matches the key embedded in this
		// JWK, as required by the standard (see RFC 7517, Section 4.7). Otherwise
		// the JWK parsed could be semantically invalid. Technically, should also
		// check key usage fields and other extensions on the cert here, but the
		// standard doesn't exactly explain how they're supposed to map from the
		// JWK representation to the X.509 extensions.
		certPub = certs[0].PublicKey
	}

	switch raw.Kty {
	case "EC":
		if raw.D != nil {
			key, err = raw.EcPrivateKey()
			if err == nil {
				keyPub = key.(*ecdsa.PrivateKey).Public()
			}
		} else {
			key, err = raw.EcPublicKey()
			keyPub = key
		}
	case "RSA":
		if raw.D != nil {
			key, err = raw.RsaPrivateKey()
			if err == nil {
				keyPub = key.(*rsa.PrivateKey).Public()
			}
		} else {
			key, err = raw.RsaPublicKey()
			keyPub = key
		}
	case "oct":
		if certPub != nil {
			return errors.New("invalid JWK, found 'oct' (symmetric) key with cert chain")
		}
		key, err = raw.SymmetricKey()
	case "OKP":
		if raw.Crv == "Ed25519" && raw.X != nil {
			if raw.D != nil {
				key, err = raw.EdPrivateKey()
				if err == nil {
					keyPub = key.(ed25519.PrivateKey).Public()
				}
			} else {
				key, err = raw.EdPublicKey()
				keyPub = key
			}
		} else {
			err = fmt.Errorf("unknown curve %s'", raw.Crv)
		}
	default:
		err = fmt.Errorf("unknown json web key type '%s'", raw.Kty)
	}

	if err != nil {
		return
	}

	if certPub != nil && keyPub != nil {
		if !reflect.DeepEqual(certPub, keyPub) {
			return errors.New("invalid JWK, public keys in key and x5c fields do not match")
		}
	}

	*k = SigningKey{Key: key, KeyID: raw.Kid, Algorithm: algorithm.SigningAlgorithmFromString(raw.Alg), Certificates: certs}

	if !k.Algorithm.IsValid() {
		return fmt.Errorf("invalid JWK, unknown algorithm '%s'", raw.Alg)
	}

	if raw.X5U != "" {
		k.CertificatesURL, err = url.Parse(raw.X5U)
		if err != nil {
			return fmt.Errorf("invalid JWK, x5u header is invalid URL: %w", err)
		}
	}

	k.CertificateThumbprintSHA1 = raw.X5TSha1
	k.CertificateThumbprintSHA256 = raw.X5TSha256

	x5tSHA1Len := len(k.CertificateThumbprintSHA1)
	x5tSHA256Len := len(k.CertificateThumbprintSHA256)
	if x5tSHA1Len > 0 && x5tSHA1Len != sha1.Size {
		return errors.New("invalid JWK, x5t header is of incorrect size")
	}
	if x5tSHA256Len > 0 && x5tSHA256Len != sha256.Size {
		return errors.New("invalid JWK, x5t#S256 header is of incorrect size")
	}

	// If certificate chain *and* thumbprints are set, verify correctness.
	if len(k.Certificates) > 0 {
		leaf := k.Certificates[0]
		sha1sum := sha1.Sum(leaf.Raw)
		sha256sum := sha256.Sum256(leaf.Raw)

		if len(k.CertificateThumbprintSHA1) > 0 && !bytes.Equal(sha1sum[:], k.CertificateThumbprintSHA1) {
			return errors.New("invalid JWK, x5c thumbprint does not match x5t value")
		}

		if len(k.CertificateThumbprintSHA256) > 0 && !bytes.Equal(sha256sum[:], k.CertificateThumbprintSHA256) {
			return errors.New("invalid JWK, x5c thumbprint does not match x5t#S256 value")
		}
	}

	return nil
}

func (k *SigningKey) signRsaData(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	var (
		ch         crypto.Hash
		isPKCS1v15 bool
	)

	switch k.Algorithm {
	case algorithm.SigningAlgorithmRS256:
		ch = crypto.SHA256
		isPKCS1v15 = true
	case algorithm.SigningAlgorithmRS384:
		ch = crypto.SHA384
		isPKCS1v15 = true
	case algorithm.SigningAlgorithmRS512:
		ch = crypto.SHA512
		isPKCS1v15 = true
	case algorithm.SigningAlgorithmPS256:
		ch = crypto.SHA256
	case algorithm.SigningAlgorithmPS384:
		ch = crypto.SHA384
	case algorithm.SigningAlgorithmPS512:
		ch = crypto.SHA512
	default:
		return nil, fmt.Errorf("unknown algorithm '%s' for rsa algorithm", k.Algorithm)
	}

	if !ch.Available() {
		return nil, fmt.Errorf("hash algorithm '%s' is not available", ch)
	}

	h := ch.New()
	h.Write(data)

	if isPKCS1v15 {
		return rsa.SignPKCS1v15(rand.Reader, key, ch, h.Sum(nil))
	}
	opts := rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch}
	return rsa.SignPSS(rand.Reader, key, ch, h.Sum(nil), &opts)
}

func (k *SigningKey) signHmacData(data []byte, key []byte) ([]byte, error) {
	var ch crypto.Hash
	switch k.Algorithm {
	case algorithm.SigningAlgorithmHS256:
		ch = crypto.SHA256
	case algorithm.SigningAlgorithmHS384:
		ch = crypto.SHA384
	case algorithm.SigningAlgorithmHS512:
		ch = crypto.SHA512
	default:
		return nil, fmt.Errorf("unknown algorithm '%s' for hmac algorithm", k.Algorithm)
	}

	if !ch.Available() {
		return nil, fmt.Errorf("hash algorithm '%s' is not available", ch)
	}

	h := hmac.New(ch.New, key)
	h.Write(data)

	return h.Sum(nil), nil
}

func fromEdPublicKey(pub ed25519.PublicKey, raw *jwkpb.JWK) {
	raw.Kty = "OKP"
	raw.Crv = "Ed25519"
	raw.X = pub

}

func fromRsaPublicKey(pub *rsa.PublicKey, raw *jwkpb.JWK) {
	raw.Kty = "RSA"
	raw.N = pub.N.Bytes()

	raw.E = bytesFromInt(uint64(pub.E))
}

func fromEcPublicKey(pub *ecdsa.PublicKey, raw *jwkpb.JWK) error {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return fmt.Errorf(" invalid EC key or X/Y missing)")
	}

	name, err := curveName(pub.Curve)
	if err != nil {
		return err
	}

	size := curveSize(pub.Curve)

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	if len(xBytes) > size || len(yBytes) > size {
		return fmt.Errorf("invalid EC key (X/Y too large)")
	}

	raw.Kty = "EC"
	raw.Crv = name
	raw.X = bytesFromFixedSize(xBytes, size)
	raw.Y = bytesFromFixedSize(yBytes, size)
	return nil
}

func fromEdPrivateKey(ed ed25519.PrivateKey, raw *jwkpb.JWK) {
	fromEdPublicKey(ed25519.PublicKey(ed[32:]), raw)

	raw.D = ed[0:32]
}

func fromRsaPrivateKey(rsa *rsa.PrivateKey, raw *jwkpb.JWK) error {
	if len(rsa.Primes) != 2 {
		return ErrUnsupportedKeyType
	}
	fromRsaPublicKey(&rsa.PublicKey, raw)

	raw.D = rsa.D.Bytes()
	raw.P = rsa.Primes[0].Bytes()
	raw.Q = rsa.Primes[1].Bytes()

	if rsa.Precomputed.Dp != nil {
		raw.Dp = rsa.Precomputed.Dp.Bytes()
	}
	if rsa.Precomputed.Dq != nil {
		raw.Dq = rsa.Precomputed.Dq.Bytes()
	}
	if rsa.Precomputed.Qinv != nil {
		raw.Qi = rsa.Precomputed.Qinv.Bytes()
	}

	return nil
}

func fromEcPrivateKey(ec *ecdsa.PrivateKey, raw *jwkpb.JWK) error {
	err := fromEcPublicKey(&ec.PublicKey, raw)
	if err != nil {
		return err
	}

	if ec.D == nil {
		return errors.New("invalid EC private key")
	}

	raw.D = bytesFromFixedSize(ec.D.Bytes(), dSize(ec.PublicKey.Curve))

	return nil
}

// dSize returns the size in octets for the "d" member of an elliptic curve
// private key.
// The length of this octet string MUST be ceiling(log-base-2(n)/8)
// octets (where n is the order of the curve).
// https://tools.ietf.org/html/rfc7518#section-6.2.2.1
func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / 8
	if bitLen%8 != 0 {
		size++
	}
	return size
}

func fromSymmetricKey(key []byte, raw *jwkpb.JWK) {
	raw.Kty = "oct"
	raw.K = key
}

// Get JOSE name of curve
func curveName(crv elliptic.Curve) (string, error) {
	switch crv {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("go-jose/go-jose: unsupported/unknown elliptic curve")
	}
}

// Get size of curve in bytes
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / 8
	mod := bits % 8

	if mod == 0 {
		return div
	}

	return div + 1
}

func parseCertificateChain(chain [][]byte) ([]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, nil
	}
	out := make([]*x509.Certificate, len(chain))
	for i, cert := range chain {
		var err error
		out[i], err = x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func bytesFromInt(num uint64) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	return bytes.TrimLeft(data, "\x00")
}

func bytesFromFixedSize(data []byte, length int) []byte {
	if len(data) > length {
		panic("invalid call to B64FromFixedSize (len(data) > length)")
	}
	pad := make([]byte, length-len(data))
	return append(pad, data...)
}
