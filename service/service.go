// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"github.com/blockysource/authz/cache"
	"github.com/blockysource/authz/deps"
	grpcports "github.com/blockysource/authz/ports/grpc"
)

// Service is an abstraction used to access the 'authz' service.
// It contains all the singletons, caches, ports and other objects that are used by the service.
type Service struct {
	deps  *deps.Dependencies
	cache *cache.Containers
	grpc  *grpcports.Services
}
