// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

//go:generate go run github.com/google/wire/cmd/wire
//go:build wireinject

package postgresadmin

import (
	"log/slog"

	"github.com/google/wire"
)

// NewKeysStorage creates a new instance of KeysStorage.
func NewKeysStorage(lh slog.Handler) (*KeysStorage, func(), error) {
	wire.Build(
		newLogger,

		wire.Struct(new(KeysStorage), "*"),
	)
	return nil, nil, nil
}

func newLogger(lh slog.Handler) *slog.Logger {
	return slog.New(lh).With(
		"service", "authz",
		"module", "persistence",
		"component", "admin",
		"driver", "postgres",
	)
}
