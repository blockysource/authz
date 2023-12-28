// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"github.com/blockysource/authz/logic/keys"
	"strings"
	"sync"

	"github.com/google/btree"
)

// KeySetsContainer is a singleton container for the service key sets.
type KeySetsContainer struct {
	l       sync.Mutex
	keySets *btree.BTreeG[projectKeySetNode]
}

func newKeySetsContainer() *KeySetsContainer {
	return &KeySetsContainer{
		keySets: btree.NewG[projectKeySetNode](2, lessKeySetFunc),
	}
}

// Acquire acquires a lock for the container.
// NOTE: The lock must be unlocked after usage.
// It is recommended to use the defer statement.
func (k *KeySetsContainer) Acquire() *KeySetsContainerLock {
	k.l.Lock()
	return &KeySetsContainerLock{k: k}
}

// KeySetsContainerLock is a lock for the container.
type KeySetsContainerLock struct {
	k      *KeySetsContainer
	unlock sync.Once
}

// Release unlocks the container.
func (k *KeySetsContainerLock) Release() {
	k.unlock.Do(func() {
		k.k.l.Unlock()
	})
}

// NewKeySetsContainer creates a new instance of KeySetsContainer.
func NewKeySetsContainer() *KeySetsContainer {
	return &KeySetsContainer{
		keySets: btree.NewG[projectKeySetNode](2, lessKeySetFunc),
	}
}

func lessKeySetFunc(a, b projectKeySetNode) bool {
	return strings.Compare(a.projectID, b.projectID) < 0
}

type projectKeySetNode struct {
	projectID string
	keySet    *keys.KeySet
}

// GetProjectKeySet returns the key set for the given project.
// This function always returns a key set, even if it is empty.
// If the function returns false, the new key set was created and assigned to the project.
func (k *KeySetsContainer) GetProjectKeySet(projectID string) (*keys.KeySet, bool) {
	node, ok := k.keySets.Get(projectKeySetNode{projectID: projectID})
	if ok {
		return node.keySet, true
	}
	ks := keys.NewKeySet()
	k.keySets.ReplaceOrInsert(projectKeySetNode{projectID: projectID, keySet: ks})
	return ks, false
}
