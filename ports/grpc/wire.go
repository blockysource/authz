// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

//go:build wireinject

//go:generate go run github.com/google/wire/cmd/wire

package grpcports

import (
	"github.com/blockysource/authz/cache"
	"github.com/blockysource/authz/deps"
	admingrpc "github.com/blockysource/authz/ports/grpc/admin"
	"github.com/google/wire"
)

// NewServices creates a new instance of the admin gRPC services.
func NewServices(d *deps.Dependencies, c *cache.Containers) (*Services, func(), error) {
	wire.Build(
		admingrpc.NewServices,
		wire.Struct(new(Services), "*"),
	)
	return nil, nil, nil
}
