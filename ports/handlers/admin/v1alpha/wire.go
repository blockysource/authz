// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

//go:build wireinject

//go:generate go run github.com/google/wire/cmd/wire

package adminv1alpha

import (
	"github.com/blockysource/authz/cache"
	"github.com/blockysource/authz/deps"
	"github.com/blockysource/authz/logic/clients"
	"github.com/blockysource/authz/logic/keys"
	"github.com/blockysource/authz/persistence/admindb"
	secrethash "github.com/blockysource/go-secret-hash"
	"github.com/google/wire"
	"log/slog"
)

// NewClientsServiceHandler creates a new instance of the ClientsServiceHandler.
func NewClientsServiceHandler(*deps.Dependencies, *cache.Containers) (*ClientsServiceHandler, func(), error) {
	wire.Build(
		newInitedClientsServiceHandler,
	)
	return nil, nil, nil
}

func newInitedClientsServiceHandler(d *deps.Dependencies, c *cache.Containers) (*ClientsServiceHandler, func(), error) {
	cs, fn, err := newClientsServiceHandler(d, c)
	if err != nil {
		return nil, nil, err
	}

	cs.init()
	return cs, fn, nil
}

// newClientsServiceHandler creates a new instance of the ClientsServiceHandler.
func newClientsServiceHandler(d *deps.Dependencies, cache *cache.Containers) (*ClientsServiceHandler, func(), error) {
	wire.Build(
		deps.ProvideLogger,
		newClientsLogger,
		admindb.NewClientsStorage,
		newClientsSecretHasher,
		clients.DefaultOptions,
		clients.NewClientsLogic,
		wire.Struct(new(ClientsServiceHandler), "*"),
	)
	return nil, nil, nil
}

func newClientsLogger(h slog.Handler) *slog.Logger {
	return newLogger(h, "clients")
}

func newClientsSecretHasher() (*secrethash.Hasher, error) {
	return secrethash.NewHasher(
		secrethash.DefaultArgon2HashingAlgorith(),
	)
}

//
// Keys service handler
//

// NewKeysServiceHandler creates a new instance of the KeysServiceHandler.
func NewKeysServiceHandler(*deps.Dependencies, *cache.Containers) (*KeysServiceHandler, func(), error) {
	wire.Build(
		newInitedKeysServiceHandler,
	)
	return nil, nil, nil
}

func newInitedKeysServiceHandler(d *deps.Dependencies, c *cache.Containers) (*KeysServiceHandler, func(), error) {
	ks, fn, err := newKeysServiceHandler(d, c)
	if err != nil {
		return nil, nil, err
	}

	ks.init()
	return ks, fn, nil
}

// newKeysServiceHandler creates a new instance of the KeysServiceHandler.
func newKeysServiceHandler(d *deps.Dependencies, cache *cache.Containers) (*KeysServiceHandler, func(), error) {
	wire.Build(
		deps.ProvideLogger,
		newKeysLogger,
		admindb.NewKeysStorage,
		keys.DefaultGenerator,
		wire.Struct(new(KeysServiceHandler), "*"),
	)
	return nil, nil, nil
}

func newKeysLogger(h slog.Handler) *slog.Logger {
	return newLogger(h, "keys")
}

func newLogger(h slog.Handler, handler string) *slog.Logger {
	l := slog.New(h)
	return l.With(
		slog.String("service", "authz"),
		slog.String("component", "admin"),
		slog.String("handler", handler),
	)
}
