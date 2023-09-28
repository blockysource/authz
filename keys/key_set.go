// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keys

import (
	"sort"
	"sync"
)

// KeySet is a set of the signing and verification keys.
type KeySet struct {
	l sync.RWMutex

	// signKeys is the signing key resource name.
	signKeys []*SigningKey

	// verifyKeys is the verification key resource name.
	verifyKeys []*VerificationKey
}

// ReplaceSigningKey replaces the signing key for its KeyID variable.
// A KeySet can only have one revision of signing key for specific KeyID.
// The keys are
func (k *KeySet) ReplaceSigningKey(signKey *SigningKey) {
	k.l.Lock()
	defer k.l.Unlock()

	var found bool
	for i, key := range k.signKeys {
		if key.KeyID == signKey.KeyID {
			k.signKeys[i] = signKey
			found = true
		}
	}

	if !found {
		k.signKeys = append(k.signKeys, signKey)
	}

	// Sort the signing key set.
	sort.Slice(k.signKeys, func(i, j int) bool {
		if k.signKeys[i].Priority == k.signKeys[j].Priority {
			return k.signKeys[i].Algorithm < k.signKeys[j].Algorithm
		}
		return k.signKeys[i].Priority < k.signKeys[j].Priority
	})
}

// FindVerificationKey returns the verification key that matches the given kid.
func (k *KeySet) FindVerificationKey(kid string) *VerificationKey {
	k.l.RLock()
	defer k.l.RUnlock()

	for _, key := range k.verifyKeys {
		if key.ID == kid {
			return key
		}
	}
	return nil
}

// DropVerificationKey drops the verification key that matches given revision identifier.
// The revision id matches the kid of the verification key.
func (k *KeySet) DropVerificationKey(revisionID string) {
	k.l.Lock()
	defer k.l.Unlock()

	for i, key := range k.verifyKeys {
		if key.ID == revisionID {
			k.verifyKeys = append(k.verifyKeys[:i], k.verifyKeys[i+1:]...)
		}
	}
}

