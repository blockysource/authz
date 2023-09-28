// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"strings"
	"sync"

	"github.com/google/btree"

	"github.com/blockysource/authz/keys"
)

// KeySetsContainer is a singleton container for the service key sets.
type KeySetsContainer struct {
	l       sync.RWMutex
	keySets *btree.BTreeG[projectKeySetNode]
}

// NewKeySetsContainer creates a new instance of KeySetsContainer.
func NewKeySetsContainer() *KeySetsContainer {
	return &KeySetsContainer{
		keySets: btree.NewG[projectKeySetNode](2, lessFunc),
	}
}

func lessFunc(a, b projectKeySetNode) bool {
	return strings.Compare(a.Project, b.Project) < 0
}

type projectKeySetNode struct {
	Project string
	KeySet  *keys.KeySet
}

// GetProjectKeySet returns the key set for the given project.
func (k *KeySetsContainer) GetProjectKeySet(project string) *keys.KeySet {
	k.l.RLock()
	defer k.l.RUnlock()
	node, ok := k.keySets.Get(projectKeySetNode{Project: project})
	if !ok {
		return nil
	}
	return node.KeySet
}
