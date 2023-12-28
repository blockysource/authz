// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keysevents

import (
	"github.com/blockysource/authz/cache"
	"github.com/blockysource/authz/persistence/localdb"
	"gocloud.dev/pubsub"
	"log/slog"
)

// Handler is a key rotated event handler.
type Handler struct {
	log *slog.Logger

	// The cache container for the keys.
	keys *cache.KeySetsContainer

	// keyRotated is the key rotated event subscription.
	keyRotated *pubsub.Subscription

	// storage for the keys.
	storage *localdb.KeysStorage
}
