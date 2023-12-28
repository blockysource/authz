// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package deps

import (
	"google.golang.org/grpc"
	"log/slog"

	"gocloud.dev/pubsub"
	"gocloud.dev/secrets"

	"github.com/blockysource/blockysql"
)

// Dependencies is a set of dependencies required by the service.
type Dependencies struct {
	// DB is a database connection used by the persistence layer.
	DB *blockysql.DB

	// Topics is a set of pubsub topics, used by the service.
	Topics Topics

	// Logger is a logger handler used by the service.
	Logger slog.Handler

	// KeySecretKeeper is a secret used to encrypt keys.
	KeySecretKeeper *secrets.Keeper

	// GRPCServer is a gRPC server used by the service to expose gRPC endpoints.
	// A gRPC server should be secured with TLS certificates and ports.
	GRPCServer *grpc.Server

	// UnsafeGRPCServer is a gRPC server used by the service to expose its unsafe gRPC endpoints.
	// An unsafe grpc server should be secured with different TLS certificates and ports than the main gRPC server.
	UnsafeGRPCServer *grpc.Server
}

// Topics is a set of pubsub topics, used by the service.
type Topics struct {
	// KeyCreated is a topic for key revision created events.
	KeyCreated *pubsub.Topic

	// KeyRevoked is a topic for key revision revoked events.
	KeyRevoked *pubsub.Topic
}

// ProvideLogger provides a logger handler.
func ProvideLogger(d *Dependencies) slog.Handler {
	return d.Logger
}

// ProvideDB provides a database connection.
func ProvideDB(d *Dependencies) *blockysql.DB {
	return d.DB
}
