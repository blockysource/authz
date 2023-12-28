// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package localtypes

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/blockysource/authz/types/algorithm"
)

// Key represents a key used for signing.
type Key struct {
	// CoreID is the unique identifier of the signing key.
	CoreID string

	// KeyID is the revision identifier of the signing key.
	KeyID string

	// CreatedAt is the creation time of the key.
	CreatedAt time.Time

	// Algorithm is the signing algorithm of the signing key.
	Algorithm algorithm.SigningAlgorithm

	// Priority is the priority of the signing key.
	Priority int

	// PrivateKey is the binary form of a private key.
	// To decode it into a private key, use the method: 'ParsePrivateKey'.
	PrivateKey []byte
}

// ParsePrivateKey parses a private key from a binary form.
func (k *Key) ParsePrivateKey() (crypto.PrivateKey, error) {
	switch {
	case k.Algorithm.IsAsymmetric():
		return x509.ParsePKCS8PrivateKey(k.PrivateKey)
	case k.Algorithm.IsHMAC():
		return k.PrivateKey, nil
	case k.Algorithm.IsNone():
		return nil, nil
	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}
