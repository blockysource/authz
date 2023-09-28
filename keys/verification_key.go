// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"

	"github.com/blockysource/authz/types"
	"github.com/blockysource/go-genproto/blocky/authz/type/jwkpb"
)

// ErrInvalidSignature is returned when the signature is invalid.
var ErrInvalidSignature = errors.New("invalid signature")

// VerificationKey represents a verification key.
type VerificationKey struct {
	// ID is the unique identifier of the key.
	ID string

	// Key is the signing key raw value, depending on the algorithm type it can be:
	// - []byte for HMAC
	// - *rsa.PublicKey for RSA and RSASSA-PSS
	// - *ecdsa.PublicKey for ECDSA
	// - ed25519.PublicKey for EdDSA
	Key any

	// Algorithm is the signing algorithm associated with the key.
	Algorithm                   types.SigningAlgorithm
	Certificates                []*x509.Certificate
	CertificatesURL             *url.URL
	CertificateThumbprintSHA1   []byte
	CertificateThumbprintSHA256 []byte
}

// MarshalPKCS8 marshals the signing key to PKCS#8 format.
func (k *VerificationKey) MarshalPKCS8() ([]byte, error) {
	if kb, ok := k.Key.([]byte); ok {
		return kb, nil
	}
	return x509.MarshalPKIXPublicKey(k.Key)
}

// Verify verifies the signature of the data using the signing key.
func (k *VerificationKey) Verify(data, signature []byte) error {
	if k.Algorithm == types.SigningAlgorithmNone {
		if len(signature) == 0 {
			return nil
		}
		return ErrInvalidSignature
	}

	switch key := k.Key.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(key, data, signature) {
			return ErrInvalidSignature
		}
	case *ecdsa.PublicKey:
		var (
			ch crypto.Hash
			ks int
		)
		switch k.Algorithm {
		case types.SigningAlgorithmES256:
			ch = crypto.SHA256
			ks = 32
		case types.SigningAlgorithmES384:
			ch = crypto.SHA384
			ks = 48
		case types.SigningAlgorithmES512:
			ch = crypto.SHA512
			ks = 64
		default:
			return fmt.Errorf("unknown algorithm '%s' for ecdsa algorithm", k.Algorithm)
		}

		if len(signature) != 2*ks {
			return ErrInvalidSignature
		}

		if !ch.Available() {
			return fmt.Errorf("hash '%s' is not available", ch)
		}

		h := ch.New()
		h.Write(data)

		r := new(big.Int).SetBytes(signature[:ks])
		s := new(big.Int).SetBytes(signature[ks:])

		if !ecdsa.Verify(key, h.Sum(nil), r, s) {
			return ErrInvalidSignature
		}
	case *rsa.PublicKey:
		var (
			ch         crypto.Hash
			isPKCS1v15 bool
		)
		switch k.Algorithm {
		case types.SigningAlgorithmRS256:
			ch = crypto.SHA256
			isPKCS1v15 = true
		case types.SigningAlgorithmRS384:
			ch = crypto.SHA384
			isPKCS1v15 = true
		case types.SigningAlgorithmRS512:
			ch = crypto.SHA512
			isPKCS1v15 = true
		case types.SigningAlgorithmPS256:
			ch = crypto.SHA256
		case types.SigningAlgorithmPS384:
			ch = crypto.SHA384
		case types.SigningAlgorithmPS512:
			ch = crypto.SHA512
		default:
			return fmt.Errorf("unknown algorithm '%s' for rsa algorithm", k.Algorithm)
		}
		if !ch.Available() {
			return fmt.Errorf("hash '%s' is not available", ch)
		}
		h := ch.New()
		h.Write(data)

		if isPKCS1v15 {
			if err := rsa.VerifyPKCS1v15(key, ch, h.Sum(nil), signature); err != nil {
				return ErrInvalidSignature
			}
		} else {
			opts := rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: ch}
			if err := rsa.VerifyPSS(key, ch, h.Sum(nil), signature, &opts); err != nil {
				return ErrInvalidSignature
			}
		}
	case []byte:
		var ch crypto.Hash
		switch k.Algorithm {
		case types.SigningAlgorithmHS256:
			ch = crypto.SHA256
		case types.SigningAlgorithmHS384:
			ch = crypto.SHA384
		case types.SigningAlgorithmHS512:
			ch = crypto.SHA512
		default:
			return fmt.Errorf("unknown algorithm '%s' for hmac algorithm", k.Algorithm)
		}

		if !ch.Available() {
			return fmt.Errorf("hash '%s' is not available", ch)
		}

		h := hmac.New(ch.New, key)
		h.Write(data)

		if !hmac.Equal(signature, h.Sum(nil)) {
			return ErrInvalidSignature
		}
	default:
		return fmt.Errorf("unknown key type '%s'", reflect.TypeOf(key))
	}
	return nil
}

// SetProto returns a protobuf JSON Web Key representation of the verification key.
func (k *VerificationKey) SetProto(jwk *jwkpb.JWK) error {
	// Reset the input jwk to a blank state.
	jwk.Reset()

	var err error
	switch key := k.Key.(type) {
	case ed25519.PublicKey:
		fromEdPublicKey(key, jwk)
	case *ecdsa.PublicKey:
		err = fromEcPublicKey(key, jwk)
	case *rsa.PublicKey:
		fromRsaPublicKey(key, jwk)
	case []byte:
		fromSymmetricKey(key, jwk)
	default:
		return fmt.Errorf("unknown key type '%s'", reflect.TypeOf(key))
	}

	if err != nil {
		return err
	}

	jwk.Kid = k.ID
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
func (k *VerificationKey) FromProto(raw *jwkpb.JWK) (err error) {
	if raw.IsPrivate() {
		return errors.New("input JWK is a private key, not a public key")
	}

	certs, err := parseCertificateChain(raw.X5C)
	if err != nil {
		return fmt.Errorf("failed to unmarshal x5c field: %s", err)
	}

	var key any
	var certPub any

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
			return errors.New("input JWK is a private key, not a public key")
		}
		key, err = raw.EcPublicKey()
	case "RSA":
		if raw.D != nil {
			return errors.New("input JWK is a private key, not a public key")
		}
		key, err = raw.RsaPublicKey()
	case "oct":
		if certPub != nil {
			return errors.New("invalid JWK, found 'oct' (symmetric) key with cert chain")
		}
		key, err = raw.SymmetricKey()
	case "OKP":
		if raw.Crv == "Ed25519" && raw.X != nil {
			if raw.D != nil {
				return errors.New("input JWK is a private key, not a public key")
			}
			key, err = raw.EdPublicKey()
		} else {
			err = fmt.Errorf("unknown curve %s'", raw.Crv)
		}
	default:
		err = fmt.Errorf("unknown json web key type '%s'", raw.Kty)
	}

	if err != nil {
		return
	}

	if certPub != nil && key != nil {
		if !reflect.DeepEqual(certPub, key) {
			return errors.New("invalid JWK, public keys in key and x5c fields do not match")
		}
	}

	*k = VerificationKey{Key: key, ID: raw.Kid, Algorithm: types.SigningAlgorithmFromString(raw.Alg), Certificates: certs}
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
