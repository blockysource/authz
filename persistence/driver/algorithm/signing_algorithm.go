// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package algorithm

import (
	"database/sql/driver"
	"fmt"

	"github.com/blockysource/authz/types"
)

// SigningAlgorithm represents the algorithm used to sign the instance access token.
type SigningAlgorithm int

const (
	// SigningAlgorithmNone is a type for None signing algorithm.
	SigningAlgorithmNone = SigningAlgorithm(types.SigningAlgorithmNone)
	// SigningAlgorithmHS256 is a type for HS256 signing algorithm.
	SigningAlgorithmHS256 = SigningAlgorithm(types.SigningAlgorithmHS256)
	// SigningAlgorithmHS384 is a type for HS384 signing algorithm.
	SigningAlgorithmHS384 = SigningAlgorithm(types.SigningAlgorithmHS384)
	// SigningAlgorithmHS512 is a type for HS512 signing algorithm.
	SigningAlgorithmHS512 = SigningAlgorithm(types.SigningAlgorithmHS512)
	// SigningAlgorithmRS256 is a type for RS256 signing algorithm.
	SigningAlgorithmRS256 = SigningAlgorithm(types.SigningAlgorithmRS256)
	// SigningAlgorithmRS384 is a type for RS384 signing algorithm.
	SigningAlgorithmRS384 = SigningAlgorithm(types.SigningAlgorithmRS384)
	// SigningAlgorithmRS512 is a type for RS512 signing algorithm.
	SigningAlgorithmRS512 = SigningAlgorithm(types.SigningAlgorithmRS512)
	// SigningAlgorithmES256 is a type for ES256 signing algorithm.
	SigningAlgorithmES256 = SigningAlgorithm(types.SigningAlgorithmES256)
	// SigningAlgorithmES384 is a type for ES384 signing algorithm.
	SigningAlgorithmES384 = SigningAlgorithm(types.SigningAlgorithmES384)
	// SigningAlgorithmES512 is a type for ES512 signing algorithm.
	SigningAlgorithmES512 = SigningAlgorithm(types.SigningAlgorithmES512)
	// SigningAlgorithmPS256 is a type for PS256 signing algorithm.
	SigningAlgorithmPS256 = SigningAlgorithm(types.SigningAlgorithmPS256)
	// SigningAlgorithmPS384 is a type for PS384 signing algorithm.
	SigningAlgorithmPS384 = SigningAlgorithm(types.SigningAlgorithmPS384)
	// SigningAlgorithmPS512 is a type for PS512 signing algorithm.
	SigningAlgorithmPS512 = SigningAlgorithm(types.SigningAlgorithmPS512)
	// SigningAlgorithmEdDSA is a type for EdDSA signing algorithm.
	SigningAlgorithmEdDSA = SigningAlgorithm(types.SigningAlgorithmEdDSA)
)

var signingAlgorithmNames = [SigningAlgorithmEdDSA + 1]string{
	SigningAlgorithmNone:  "NONE",
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

// MarshalText implements the encoding.TextMarshaler interface.
func (a SigningAlgorithm) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (a *SigningAlgorithm) UnmarshalText(text []byte) error {
	txt := string(text)
	for i, name := range signingAlgorithmNames {
		if name == txt {
			*a = SigningAlgorithm(i)
			return nil
		}
	}
	return fmt.Errorf("algorithm: unknown signing algorithm %q", text)
}

// Scan implements the sql.Scanner interface.
func (a *SigningAlgorithm) Scan(src any) error {
	switch st := src.(type) {
	case nil:
		*a = SigningAlgorithmNone
		return nil
	case []byte:
		return a.UnmarshalText(st)
	case string:
		return a.UnmarshalText([]byte(st))
	default:
		return fmt.Errorf("algorithm: cannot scan type %T into algorithm.SigningAlgorithm", st)
	}
}

// Value implements the driver.Valuer interface.
func (a SigningAlgorithm) Value() (driver.Value, error) {
	return a.String(), nil
}
