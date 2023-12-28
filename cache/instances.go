// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"sync"

	"github.com/google/btree"

	localtypes "github.com/blockysource/authz/types/local"
)

// InstancesContainer is a container of instances.
type InstancesContainer struct {
	l    sync.RWMutex
	tree *btree.BTreeG[instanceTreeNode]
}

func newInstancesContainer() *InstancesContainer {
	return &InstancesContainer{
		tree: btree.NewG[instanceTreeNode](2, lessInstancesFunc),
	}
}

func lessInstancesFunc(a, b instanceTreeNode) bool {
	return a.projectID < b.projectID
}

// GetInstance returns an instance by project identifier.
func (c *InstancesContainer) GetInstance(projectID string) (*localtypes.Instance, bool) {
	c.l.RLock()
	defer c.l.RUnlock()

	out, ok := c.tree.Get(instanceTreeNode{projectID: projectID})
	if !ok {
		return nil, false
	}
	return out.inst, true
}

// ReplaceOrInsertInstance replaces or inserts an instance.
func (c *InstancesContainer) ReplaceOrInsertInstance(inst *localtypes.Instance) {
	c.l.Lock()
	defer c.l.Unlock()

	c.tree.ReplaceOrInsert(instanceTreeNode{
		projectID: inst.ProjectID,
		inst:      inst,
	})
}

type instanceTreeNode struct {
	// projectID is the project identifier of the instance.
	projectID string

	inst *localtypes.Instance
}
