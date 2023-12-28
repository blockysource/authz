// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"

	"github.com/blockysource/authz/types/algorithm"
)

// SigningKeyGenerator is a key crypto StandardGenerator
type SigningKeyGenerator interface {
	// GenerateSigningKey generates a new signing key for the given algorithm.
	GenerateSigningKey(keyID string, priority int, alg algorithm.SigningAlgorithm) (*SigningKey, error)
}

var _ SigningKeyGenerator = (*StandardGenerator)(nil)

// StandardGenerator is the default implementation of the SigningKeyGenerator interface.
type StandardGenerator struct{}

// DefaultGenerator is the default key StandardGenerator.
func DefaultGenerator() SigningKeyGenerator {
	return &StandardGenerator{}
}

// GenerateSigningKey generates a new signing key for the given algorithm.
func (g *StandardGenerator) GenerateSigningKey(coreID string, priority int, alg algorithm.SigningAlgorithm) (*SigningKey, error) {
	var (
		pk  crypto.PrivateKey
		err error
	)
	if !alg.IsValid() {
		return nil, errors.New("invalid algorithm")
	}

	if !alg.IsNone() {
		pk, err = g.newPrivateKey(alg)
		if err != nil {
			return nil, err
		}
	}

	kid, err := g.newKeyID()
	if err != nil {
		return nil, err
	}

	return &SigningKey{
		CoreID:    coreID,
		KeyID:     kid,
		Priority:  priority,
		Key:       pk,
		Algorithm: alg,
	}, nil
}

func (g *StandardGenerator) newPrivateKey(alg algorithm.SigningAlgorithm) (crypto.PrivateKey, error) {
	switch alg {
	case algorithm.SigningAlgorithmHS256:
		key := make([]byte, 32) // 256 bits
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	case algorithm.SigningAlgorithmHS384:
		key := make([]byte, 48) // 384 bits
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	case algorithm.SigningAlgorithmHS512:
		key := make([]byte, 64) // 512 bits
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	case algorithm.SigningAlgorithmES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case algorithm.SigningAlgorithmES384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case algorithm.SigningAlgorithmES512:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case algorithm.SigningAlgorithmEdDSA:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case algorithm.SigningAlgorithmRS256, algorithm.SigningAlgorithmRS384, algorithm.SigningAlgorithmRS512,
		algorithm.SigningAlgorithmPS256, algorithm.SigningAlgorithmPS384, algorithm.SigningAlgorithmPS512:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func (g *StandardGenerator) newKeyID() (string, error) {
	keyIDBytes := make([]byte, 20)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(keyIDBytes), nil
}
