// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package types

import (
	"github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"
)

// SigningAlgorithm represents the algorithm used to sign the instance access token.
type SigningAlgorithm int

const (
	// SigningAlgorithmNone is a type for None signing algorithm.
	SigningAlgorithmNone = SigningAlgorithm(signalgpb.SigningAlgorithm_NONE)
	// SigningAlgorithmHS256 is a type for HS256 signing algorithm.
	SigningAlgorithmHS256 = SigningAlgorithm(signalgpb.SigningAlgorithm_HS256)
	// SigningAlgorithmHS384 is a type for HS384 signing algorithm.
	SigningAlgorithmHS384 = SigningAlgorithm(signalgpb.SigningAlgorithm_HS384)
	// SigningAlgorithmHS512 is a type for HS512 signing algorithm.
	SigningAlgorithmHS512 = SigningAlgorithm(signalgpb.SigningAlgorithm_HS512)
	// SigningAlgorithmRS256 is a type for RS256 signing algorithm.
	SigningAlgorithmRS256 = SigningAlgorithm(signalgpb.SigningAlgorithm_RS256)
	// SigningAlgorithmRS384 is a type for RS384 signing algorithm.
	SigningAlgorithmRS384 = SigningAlgorithm(signalgpb.SigningAlgorithm_RS384)
	// SigningAlgorithmRS512 is a type for RS512 signing algorithm.
	SigningAlgorithmRS512 = SigningAlgorithm(signalgpb.SigningAlgorithm_RS512)
	// SigningAlgorithmES256 is a type for ES256 signing algorithm.
	SigningAlgorithmES256 = SigningAlgorithm(signalgpb.SigningAlgorithm_ES256)
	// SigningAlgorithmES384 is a type for ES384 signing algorithm.
	SigningAlgorithmES384 = SigningAlgorithm(signalgpb.SigningAlgorithm_ES384)
	// SigningAlgorithmES512 is a type for ES512 signing algorithm.
	SigningAlgorithmES512 = SigningAlgorithm(signalgpb.SigningAlgorithm_ES512)
	// SigningAlgorithmPS256 is a type for PS256 signing algorithm.
	SigningAlgorithmPS256 = SigningAlgorithm(signalgpb.SigningAlgorithm_PS256)
	// SigningAlgorithmPS384 is a type for PS384 signing algorithm.
	SigningAlgorithmPS384 = SigningAlgorithm(signalgpb.SigningAlgorithm_PS384)
	// SigningAlgorithmPS512 is a type for PS512 signing algorithm.
	SigningAlgorithmPS512 = SigningAlgorithm(signalgpb.SigningAlgorithm_PS512)
	// SigningAlgorithmEdDSA is a type for EdDSA signing algorithm.
	SigningAlgorithmEdDSA = SigningAlgorithm(signalgpb.SigningAlgorithm_EdDSA)
)

var signingAlgorithmNames = [SigningAlgorithmEdDSA + 1]string{
	SigningAlgorithmNone:  "None",
	SigningAlgorithmHS256: "HS256",
	SigningAlgorithmHS384: "HS384",
	SigningAlgorithmHS512: "HS512",
	SigningAlgorithmRS256: "RS256",
	SigningAlgorithmRS384: "RS384",
	SigningAlgorithmRS512: "RS512",
	SigningAlgorithmES256: "ES256",
	SigningAlgorithmES384: "ES384",
	SigningAlgorithmES512: "ES512",
	SigningAlgorithmPS256: "PS256",
	SigningAlgorithmPS384: "PS384",
	SigningAlgorithmPS512: "PS512",
	SigningAlgorithmEdDSA: "EdDSA",
}

// String implements the fmt.Stringer interface.
func (a SigningAlgorithm) String() string {
	if a < 0 || a > SigningAlgorithmEdDSA {
		return "UNKNOWN"
	}
	return signingAlgorithmNames[a]
}

// SigningAlgorithmFromString returns the signing algorithm from the given string.
func SigningAlgorithmFromString(s string) SigningAlgorithm {
	for i, name := range signingAlgorithmNames {
		if name == s {
			return SigningAlgorithm(i)
		}
	}
	return SigningAlgorithm(0)
}

// IsValid returns true if the signing algorithm is valid.
func (a SigningAlgorithm) IsValid() bool {
	return a >= SigningAlgorithmNone && a <= SigningAlgorithmEdDSA
}

// IsRSA returns true if the signing algorithm is RSA.
func (a SigningAlgorithm) IsRSA() bool {
	return a >= SigningAlgorithmRS256 && a <= SigningAlgorithmRS512 ||
		a >= SigningAlgorithmPS256 && a <= SigningAlgorithmPS512
}

// IsECDSA returns true if the signing algorithm is ECDSA.
func (a SigningAlgorithm) IsECDSA() bool {
	return a >= SigningAlgorithmES256 && a <= SigningAlgorithmES512
}

// IsEdDSA returns true if the signing algorithm is EdDSA.
func (a SigningAlgorithm) IsEdDSA() bool {
	return a == SigningAlgorithmEdDSA
}

// IsHMAC returns true if the signing algorithm is HMAC.
func (a SigningAlgorithm) IsHMAC() bool {
	return a >= SigningAlgorithmHS256 && a <= SigningAlgorithmHS512
}

// IsNone returns true if the signing algorithm is None.
func (a SigningAlgorithm) IsNone() bool {
	return a == SigningAlgorithmNone
}

// IsAsymmetric returns true if the signing algorithm is asymmetric.
func (a SigningAlgorithm) IsAsymmetric() bool {
	return a >= SigningAlgorithmRS256 && a <= SigningAlgorithmEdDSA
}

// IsSymmetric returns true if the signing algorithm is symmetric.
func (a SigningAlgorithm) IsSymmetric() bool {
	return a >= SigningAlgorithmHS256 && a <= SigningAlgorithmHS512
}
