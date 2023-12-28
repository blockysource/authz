// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package cache

// Containers is a container containing all cache containers.
type Containers struct {
	keySets   *KeySetsContainer
	instances *InstancesContainer
	resources *ResourcesContainer
}

// NewContainers creates a new instance of the cache containers.
func NewContainers() *Containers {
	return &Containers{
		keySets:   newKeySetsContainer(),
		instances: newInstancesContainer(),
		resources: newResourcesContainer(),
	}
}
