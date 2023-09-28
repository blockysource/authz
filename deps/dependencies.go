// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package deps

import (
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
}

// Topics is a set of pubsub topics, used by the service.
type Topics struct {
	// KeyRevisionCreated is a topic for key revision created events.
	KeyRevisionCreated *pubsub.Topic

	// KeyRevisionRevoked is a topic for key revision revoked events.
	KeyRevisionRevoked *pubsub.Topic
}
