// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keys

import (
	localtypes "github.com/blockysource/authz/types/local"
	"sort"
	"strings"
	"sync"

	"github.com/blockysource/authz/types/algorithm"
)

// KeySet is a set of the signing and verification keys.
type KeySet struct {
	// signKeys is the signing key resource name.
	signKeys struct {
		sync.RWMutex

		// By default the keys are sorted by their KeyID.
		keys []*SigningKey

		// indexKeyID is an index that gets the keys by the key core identifier.
		indexCoreID []int
		// indexRevisionID is an index that gets the keys by the key identifier.
		indexKeyID []int
		// indexPriority is an index that gets the keys by the priority.
		indexPriority []int
		// Is an index that gets the keys by the algorithm and priority.
		indexAlgorithmPriority []int
	}

	// verifyKeys is the verification key resource name.
	verifyKeys struct {
		sync.RWMutex
		keys []*VerificationKey
		// Is an index that gets the keys by the algorithm and priority.
		indexKeyID []int
	}
}

// NewKeySet creates a new instance of KeySet.
func NewKeySet() *KeySet {
	return &KeySet{}
}

// ReplaceOrInsertSigningKey replaces the signing key for its KeyID variable.
// A KeySet can only have a single signing key of given Key Core.
func (k *KeySet) ReplaceOrInsertSigningKey(key localtypes.Key) error {
	k.signKeys.Lock()
	defer k.signKeys.Unlock()

	k.verifyKeys.Lock()
	defer k.verifyKeys.Unlock()

	signKey, err := NewSigningKey(key)
	if err != nil {
		return err
	}

	idx := sort.Search(len(k.signKeys.keys), func(i int) bool {
		// Compare by using the key index by key identifier.
		sk := k.signKeys.keys[k.signKeys.indexCoreID[i]]
		return strings.Compare(key.CoreID, sk.CoreID) <= 0
	})

	if idx < len(k.signKeys.keys) && k.signKeys.keys[idx].CoreID == key.CoreID {
		// The key is found in the index.
		// Replace the key.
		k.signKeys.keys[k.signKeys.indexCoreID[idx]] = signKey
	} else {
		// The key is not found in the index.
		// Insert the key.
		k.signKeys.keys = append(k.signKeys.keys[:idx], append([]*SigningKey{signKey}, k.signKeys.keys[idx:]...)...)

		k.signKeys.indexCoreID = append(k.signKeys.indexCoreID, idx)
		k.signKeys.indexKeyID = append(k.signKeys.indexKeyID, idx)
		k.signKeys.indexPriority = append(k.signKeys.indexPriority, idx)
		k.signKeys.indexAlgorithmPriority = append(k.signKeys.indexAlgorithmPriority, idx)
	}

	// Calculate the keyID indexes.
	k.sortSigningKeyCoreIDIndexes()

	// Calculate the revisionID indexes.
	k.sortSigningKeyKeyIDIndexes()

	// Compute the priority indexes.
	k.sortSigningKeyPriorityIndexes()

	// Sort the algorithm indexes.
	k.sortSigningKeyAlgorithmPriorityIndexes()

	// Add the verification key to the KeySet.
	vk := signKey.VerificationKey()
	k.verifyKeys.keys = append(k.verifyKeys.keys, vk)
	idx = len(k.verifyKeys.keys) - 1
	k.verifyKeys.indexKeyID = append(k.verifyKeys.indexKeyID, idx)
	k.sortVerificationKeyKeyIDIndexes()
	return nil
}

// RevokeKey revokes the signing key that matches the given revision identifier.
// The revision id matches the kid of the signing key.
func (k *KeySet) RevokeKey(keyID string) {
	k.signKeys.Lock()

	// Try to get the key by its key identifier.
	idx, found := k.findSigningKeyByKeyID(keyID)
	if found {
		// Remove the key from the list.
		k.signKeys.keys = append(k.signKeys.keys[:idx], k.signKeys.keys[idx+1:]...)
		// Remove the key from the indexes.
		for i, v := range k.signKeys.indexCoreID {
			if v == idx {
				k.signKeys.indexCoreID = append(k.signKeys.indexCoreID[:i], k.signKeys.indexCoreID[i+1:]...)
				break
			}
		}

		for i, v := range k.signKeys.indexKeyID {
			if v == idx {
				k.signKeys.indexKeyID = append(k.signKeys.indexKeyID[:i], k.signKeys.indexKeyID[i+1:]...)
				break
			}
		}

		for i, v := range k.signKeys.indexPriority {
			if v == idx {
				k.signKeys.indexPriority = append(k.signKeys.indexPriority[:i], k.signKeys.indexPriority[i+1:]...)
				break
			}
		}

		for i, v := range k.signKeys.indexAlgorithmPriority {
			if v == idx {
				k.signKeys.indexAlgorithmPriority = append(k.signKeys.indexAlgorithmPriority[:i], k.signKeys.indexAlgorithmPriority[i+1:]...)
				break
			}
		}
	}
	k.signKeys.Unlock()

	k.verifyKeys.Lock()
	// Try to get the key by its key identifier.
	idx, found = k.findVerificationKeyByKeyID(keyID)
	if found {
		// Remove the key from the list.
		k.verifyKeys.keys = append(k.verifyKeys.keys[:idx], k.verifyKeys.keys[idx+1:]...)
		// Remove the key from the indexes.
		for i, v := range k.verifyKeys.indexKeyID {
			if v == idx {
				k.verifyKeys.indexKeyID = append(k.verifyKeys.indexKeyID[:i], k.verifyKeys.indexKeyID[i+1:]...)
				break
			}
		}
	}
	k.verifyKeys.Unlock()
}

// FindSigningKey returns the signing key that matches the given kid.
// The 'kid' is the SigningKey.KeyID variable.
func (k *KeySet) FindSigningKey(kid string) (*SigningKey, bool) {
	k.signKeys.RLock()
	defer k.signKeys.RUnlock()

	// Use the indexRevisionID to find the key.
	idx, found := sort.Find(len(k.signKeys.keys), func(i int) int {
		return strings.Compare(kid, k.signKeys.keys[k.signKeys.indexKeyID[i]].KeyID)
	})
	if !found {
		return nil, false
	}
	return k.signKeys.keys[idx], true
}

// FindHighestPrioritySigningKeyByAlgorithm returns the highest priority signing key that matches the given algorithm.
func (k *KeySet) FindHighestPrioritySigningKeyByAlgorithm(alg algorithm.SigningAlgorithm) (*SigningKey, bool) {
	k.signKeys.RLock()
	defer k.signKeys.RUnlock()

	// Use the indexAlgorithmPriority to find the key.
	// We can only compare the algorithm as the keys are sorted by the algorithm and priority (descending)..
	idx, found := sort.Find(len(k.signKeys.keys), func(i int) int {
		return algorithm.Compare(alg, k.signKeys.keys[k.signKeys.indexAlgorithmPriority[i]].Algorithm)
	})
	if !found {
		return nil, false
	}

	return k.signKeys.keys[idx], true
}

// FindVerificationKey returns the verification key that matches the given kid.
func (k *KeySet) FindVerificationKey(kid string) (*VerificationKey, bool) {
	k.verifyKeys.RLock()
	defer k.verifyKeys.RUnlock()

	idx, found := sort.Find(len(k.verifyKeys.keys), func(i int) int {
		return strings.Compare(kid, k.verifyKeys.keys[i].ID)
	})
	if !found {
		return nil, false
	}

	return k.verifyKeys.keys[idx], true
}

// DropVerificationKey drops the verification key that matches given key identifier.
// The key id matches the kid of the verification key.
func (k *KeySet) DropVerificationKey(revisionID string) bool {
	k.verifyKeys.Lock()
	defer k.verifyKeys.Unlock()

	idx, found := sort.Find(len(k.verifyKeys.keys), func(i int) int {
		return strings.Compare(revisionID, k.verifyKeys.keys[i].ID)
	})

	if !found {
		return false
	}

	k.verifyKeys.keys = append(k.verifyKeys.keys[:idx], k.verifyKeys.keys[idx+1:]...)
	return true
}

// FillKeys fills the keys into the KeySet.
// It groups the keys by their Core, finds the most recent one by
func (k *KeySet) FillKeys(keys []localtypes.Key) error {
	k.signKeys.Lock()
	defer k.signKeys.Unlock()

	k.verifyKeys.Lock()
	defer k.verifyKeys.Unlock()

	// Order all the keys by their Priority, CoreID, CreatedAt desc.
	sort.Slice(keys, func(i, j int) bool {
		left := keys[i]
		right := keys[j]

		if left.Priority == right.Priority {
			if left.CoreID == right.CoreID {
				return left.CreatedAt.After(right.CreatedAt)
			}
			return strings.Compare(left.CoreID, right.CoreID) < 0
		}
		return left.Priority < right.Priority
	})

	// Iterate over the keys and find the first key for each CoreID (which is the most recent one), and make it a signing key.
	// Create its paired verification key and add it to the KeySet.
	// All the other keys for given CoreID are only a verification keys.
	var curCoreID string
	for _, key := range keys {
		sk, err := NewSigningKey(key)
		if err != nil {
			return err
		}

		// If the current key is the first key for the CoreID, then it is a signing key.
		if curCoreID != key.CoreID {
			curCoreID = key.CoreID

			// Add the signing key to the KeySet.
			k.signKeys.keys = append(k.signKeys.keys, sk)
			idx := len(k.signKeys.keys) - 1
			k.signKeys.indexCoreID = append(k.signKeys.indexCoreID, idx)
			k.signKeys.indexKeyID = append(k.signKeys.indexKeyID, idx)
			k.signKeys.indexPriority = append(k.signKeys.indexPriority, idx)
			k.signKeys.indexAlgorithmPriority = append(k.signKeys.indexAlgorithmPriority, idx)
		}

		// Add the verification key to the KeySet.
		vk := sk.VerificationKey()
		k.verifyKeys.keys = append(k.verifyKeys.keys, vk)
		idx := len(k.verifyKeys.keys) - 1
		k.verifyKeys.indexKeyID = append(k.verifyKeys.indexKeyID, idx)
	}

	// All the keys are added to the key set, sort the indexes.
	k.sortSigningKeyCoreIDIndexes()
	k.sortSigningKeyKeyIDIndexes()
	k.sortSigningKeyPriorityIndexes()
	k.sortSigningKeyAlgorithmPriorityIndexes()
	k.sortVerificationKeyKeyIDIndexes()

	return nil
}

func (k *KeySet) sortVerificationKeyKeyIDIndexes() {
	sort.Slice(k.verifyKeys.indexKeyID, func(i, j int) bool {
		return strings.Compare(k.verifyKeys.keys[k.verifyKeys.indexKeyID[i]].ID, k.verifyKeys.keys[k.verifyKeys.indexKeyID[j]].ID) < 0
	})
}

func (k *KeySet) sortSigningKeyAlgorithmPriorityIndexes() {
	sort.Slice(k.signKeys.indexAlgorithmPriority, func(i, j int) bool {
		left := k.signKeys.keys[k.signKeys.indexAlgorithmPriority[i]]
		right := k.signKeys.keys[k.signKeys.indexAlgorithmPriority[j]]

		// Once the algorithms matches, we want to sort by the priority in descending order.
		if left.Algorithm == right.Algorithm {
			// NOTE: we want to have the highest priority first in the list of keys per algorithm.
			// 	 	thus, we need to sort the keys in descending order.
			return left.Priority > right.Priority
		}
		return left.Algorithm < right.Algorithm
	})
}

func (k *KeySet) sortSigningKeyPriorityIndexes() {
	sort.Slice(k.signKeys.indexPriority, func(i, j int) bool {
		return k.signKeys.keys[k.signKeys.indexPriority[i]].Priority < k.signKeys.keys[k.signKeys.indexPriority[j]].Priority
	})
}

func (k *KeySet) sortSigningKeyKeyIDIndexes() {
	sort.Slice(k.signKeys.indexKeyID, func(i, j int) bool {
		return strings.Compare(k.signKeys.keys[k.signKeys.indexKeyID[i]].KeyID, k.signKeys.keys[k.signKeys.indexKeyID[j]].KeyID) < 0
	})
}

func (k *KeySet) sortSigningKeyCoreIDIndexes() {
	sort.Slice(k.signKeys.indexCoreID, func(i, j int) bool {
		return strings.Compare(k.signKeys.keys[k.signKeys.indexCoreID[i]].CoreID, k.signKeys.keys[k.signKeys.indexCoreID[j]].CoreID) < 0
	})
}

func (k *KeySet) findSigningKeyByKeyID(keyID string) (int, bool) {
	return sort.Find(len(k.signKeys.keys), func(i int) int {
		return strings.Compare(keyID, k.signKeys.keys[k.signKeys.indexKeyID[i]].KeyID)
	})
}

func (k *KeySet) findVerificationKeyByKeyID(keyID string) (int, bool) {
	return sort.Find(len(k.verifyKeys.keys), func(i int) int {
		return strings.Compare(keyID, k.verifyKeys.keys[k.verifyKeys.indexKeyID[i]].ID)
	})
}
