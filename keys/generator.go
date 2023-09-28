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

	"github.com/blockysource/authz/types"
)

// Generator is a key crypto generator
type Generator interface {
	// GenerateSigningKey generates a new signing key for the given algorithm.
	GenerateSigningKey(keyID string, priority int, alg types.SigningAlgorithm) (*SigningKey, error)
}

var _ Generator = (*generator)(nil)

type generator struct{}

// GenerateSigningKey generates a new signing key for the given algorithm.
func (g *generator) GenerateSigningKey(keyID string, priority int, alg types.SigningAlgorithm) (*SigningKey, error) {
	pk, err := g.newPrivateKey(alg)
	if err != nil {
		return nil, err
	}

	kid, err := g.newKeyID()
	if err != nil {
		return nil, err
	}

	return &SigningKey{
		KeyID:      keyID,
		RevisionID: kid,
		Priority:   priority,
		Key:        pk,
		Algorithm:  alg,
	}, nil
}

func (g *generator) newPrivateKey(alg types.SigningAlgorithm) (crypto.PrivateKey, error) {
	switch alg {
	case types.SigningAlgorithmHS256:
		key := make([]byte, 32) // 256 bits
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	case types.SigningAlgorithmHS384:
		key := make([]byte, 48) // 384 bits
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	case types.SigningAlgorithmHS512:
		key := make([]byte, 64) // 512 bits
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	case types.SigningAlgorithmES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case types.SigningAlgorithmES384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case types.SigningAlgorithmES512:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case types.SigningAlgorithmEdDSA:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case types.SigningAlgorithmRS256, types.SigningAlgorithmRS384, types.SigningAlgorithmRS512:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func (g *generator) newKeyID() (string, error) {
	keyIDBytes := make([]byte, 20)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(keyIDBytes), nil
}
