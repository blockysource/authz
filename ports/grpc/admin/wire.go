// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

//go:build wireinject

//go:generate go run github.com/google/wire/cmd/wire

package admingrpc

import (
	"github.com/blockysource/authz/cache"
	"github.com/blockysource/authz/deps"
	adminv1alpha "github.com/blockysource/authz/ports/handlers/admin/v1alpha"
	"github.com/google/wire"
)

// NewServices creates a new instance of the admin gRPC services.
func NewServices(d *deps.Dependencies, c *cache.Containers) (*Services, func(), error) {
	wire.Build(
		adminv1alpha.NewKeysServiceHandler,
		wire.Struct(new(keysServices), "*"),
		adminv1alpha.NewClientsServiceHandler,
		wire.Struct(new(clientsServices), "*"),
		wire.Struct(new(Services), "*"),
	)
	return nil, nil, nil
}
