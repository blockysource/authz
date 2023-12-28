// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keysevents

import (
	"context"
	"github.com/blockysource/authz/persistence/localdb"
	"github.com/blockysource/authz/types"
	localtypes "github.com/blockysource/authz/types/local"
	authzeventsv1alpha "github.com/blockysource/go-genproto/blocky/authz/events/v1alpha"
	"gocloud.dev/pubsub"
	"google.golang.org/protobuf/proto"
)



func (h *Handler) onKeyRotated(ctx context.Context, msg *pubsub.Message) {
	// Decode the message as the key rotated event.
	var event authzeventsv1alpha.KeyRotated

	if err := proto.Unmarshal(msg.Body, &event); err != nil {
		h.log.ErrorContext(ctx, "failed to unmarshal key rotated event", "error", err)
		return
	}

	// Decode the key name.
	kn := types.KeyName(event.Name)

	// Get the key from the storage.
	key, err := h.storage.GetKey(ctx, localdb.GetKeyQuery{
		ProjectID: kn.Project(),
		KeyID:     kn.Key(),
	})
	if err != nil {
		h.log.ErrorContext(ctx, "failed to get key from storage", "error", err)
		return
	}

	lock := h.keys.Acquire()
	defer lock.Release()

	// Get project key set.
	keySet, ok := h.keys.GetProjectKeySet(kn.Project())
	if ok {
		if err = keySet.ReplaceOrInsertSigningKey(key); err != nil {
			h.log.ErrorContext(ctx, "failed to replace or insert signing key", "error", err)
		}
		return
	}
	// If the project key set is not defined, try refreshing the list of signing and verification keys for the project.
	var projectKeys []localtypes.Key
	projectKeys, err = h.storage.ListProjectKeys(ctx, localdb.ListProjectKeysQuery{
		ProjectID: kn.Project(),
	})
	if err != nil {
		h.log.ErrorContext(ctx, "failed to list project keys", "error", err)
		return
	}
	if err = keySet.FillKeys(projectKeys); err != nil {
		h.log.ErrorContext(ctx, "failed to fill project keys", "error", err)
		return
	}
}
