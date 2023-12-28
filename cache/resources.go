// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"sync"

	"github.com/google/btree"
	"github.com/google/uuid"

	localtypes "github.com/blockysource/authz/types/local"
)

type (
	// ResourcesContainer is a container that keeps in-memory project resource containers.
	// It is used to optimize the search of resource managers by project identifier.
	ResourcesContainer struct {
		lock sync.RWMutex
		tree *btree.BTreeG[projectResourceContainerNode]
	}

	// projectResourceContainerNode is simply a node in the btree.
	// This is used to optimize the search allocations.
	projectResourceContainerNode struct {
		projectID string
		container *ProjectResourceContainer
	}
)

func newResourcesContainer() *ResourcesContainer {
	return &ResourcesContainer{
		tree: btree.NewG[projectResourceContainerNode](2, func(a, b projectResourceContainerNode) bool {
			return a.projectID < b.projectID
		}),
	}
}

// FindProjectResources finds a project resource container by project identifier.
func (r *ResourcesContainer) FindProjectResources(projectID string) (*ProjectResourceContainer, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	// Find the project resource container by project identifier.
	out, ok := r.tree.Get(projectResourceContainerNode{projectID: projectID})
	if !ok {
		return nil, false
	}
	return out.container, true
}

// ReplaceOrInsertProjectResources replaces or inserts a project resource container.
func (r *ResourcesContainer) ReplaceOrInsertProjectResources(projectID string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.tree.ReplaceOrInsert(projectResourceContainerNode{
		projectID: projectID,
		container: newProjectResourceContainer(projectID),
	})
}

func newProjectResourceContainer(projectID string) *ProjectResourceContainer {
	return &ProjectResourceContainer{
		projectID: projectID,
		managers: struct {
			tree *btree.BTreeG[resourceTreeNode]
			lock sync.RWMutex
		}{
			tree: btree.NewG[resourceTreeNode](2, func(a, b resourceTreeNode) bool {
				return a.managerID.String() < b.managerID.String()
			}),
			lock: sync.RWMutex{},
		},
		scopes: struct {
			tree *btree.BTreeG[resourceScopeTreeNode]
			lock sync.RWMutex
		}{
			tree: btree.NewG[resourceScopeTreeNode](2, func(a, b resourceScopeTreeNode) bool {
				return a.scope < b.scope
			}),
			lock: sync.RWMutex{},
		},
	}
}

// ProjectResourceContainer represents a resource container.
// It provides a mapping
type ProjectResourceContainer struct {
	projectID string
	managers  struct {
		tree *btree.BTreeG[resourceTreeNode]
		lock sync.RWMutex
	}
	scopes struct {
		tree *btree.BTreeG[resourceScopeTreeNode]
		lock sync.RWMutex
	}
}

// FindManagerByScope finds a resource manager by given scope.
func (r *ProjectResourceContainer) FindManagerByScope(scope string) (*localtypes.ResourceManager, bool) {
	sc, ok := r.findScopeByScope(scope)
	if !ok {
		return nil, false
	}

	mn, ok := r.findManagerByID(sc.ManagerID)
	if !ok {
		return nil, false
	}

	return mn, true
}

// ReplaceOrInsertManager replaces or inserts a resource manager.
func (r *ProjectResourceContainer) ReplaceOrInsertManager(manager *localtypes.ResourceManager, scopes []localtypes.ResourcePermissionScope) {
	r.replaceOrInsertManager(manager, scopes)
	r.replaceOrInsertScopes(scopes...)
}

func (r *ProjectResourceContainer) findScopeByScope(scope string) (localtypes.ResourcePermissionScope, bool) {
	r.scopes.lock.RLock()
	defer r.scopes.lock.RUnlock()

	out, ok := r.scopes.tree.Get(resourceScopeTreeNode{scope: scope})
	if !ok {
		return localtypes.ResourcePermissionScope{}, false
	}
	return out.permission, true
}

func (r *ProjectResourceContainer) findManagerByID(managerID uuid.UUID) (*localtypes.ResourceManager, bool) {
	r.managers.lock.RLock()
	defer r.managers.lock.RUnlock()

	out, ok := r.managers.tree.Get(resourceTreeNode{managerID: managerID})
	if !ok {
		return nil, false
	}
	return out.manager, true
}

func (r *ProjectResourceContainer) replaceOrInsertManager(manager *localtypes.ResourceManager, scopes []localtypes.ResourcePermissionScope) {
	r.managers.lock.Lock()
	defer r.managers.lock.Unlock()

	tree := &resourceScopesBTree{
		lock: sync.RWMutex{},
		tree: btree.NewG[resourceScopeTreeNode](2, func(a, b resourceScopeTreeNode) bool {
			return a.scope < b.scope
		}),
	}

	for _, scope := range scopes {
		tree.tree.ReplaceOrInsert(resourceScopeTreeNode{
			scope:      scope.Scope,
			permission: scope,
		})
	}

	r.managers.tree.ReplaceOrInsert(resourceTreeNode{
		managerID: manager.ID,
		manager:   manager,
		scopes:    tree,
	})
}

func (r *ProjectResourceContainer) replaceOrInsertScopes(scopes ...localtypes.ResourcePermissionScope) {
	r.scopes.lock.Lock()
	defer r.scopes.lock.Unlock()

	for _, scope := range scopes {
		r.scopes.tree.ReplaceOrInsert(resourceScopeTreeNode{
			scope:      scope.Scope,
			permission: scope,
		})
	}
}

type resourceTreeNode struct {
	managerID uuid.UUID

	manager *localtypes.ResourceManager
	scopes  *resourceScopesBTree
}

type resourceScopesBTree struct {
	lock sync.RWMutex

	tree *btree.BTreeG[resourceScopeTreeNode]
}

type resourceScopeTreeNode struct {
	scope      string
	permission localtypes.ResourcePermissionScope
}
