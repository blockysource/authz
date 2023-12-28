// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package keysevents

import (
	"context"
	"github.com/blockysource/authz/types"
	authzeventsv1alpha "github.com/blockysource/go-genproto/blocky/authz/events/v1alpha"
	"gocloud.dev/pubsub"
	"google.golang.org/protobuf/proto"
)

func (h *Handler) onKeyRevoked(ctx context.Context, msg *pubsub.Message) {
	// Decode the message as the key revoked event.
	var event authzeventsv1alpha.KeyRevoked

	if err := proto.Unmarshal(msg.Body, &event); err != nil {
		h.log.ErrorContext(ctx, "failed to unmarshal key revoked event", "error", err)
		return
	}

	// Decode the key name.
	kn := types.KeyName(event.Name)

	lock := h.keys.Acquire()
	// Get project key set.
	keySet, ok := h.keys.GetProjectKeySet(kn.Project())
	if !ok {
		// NOTE: should it refresh the list of keys for the project?
		lock.Release()
		h.log.WarnContext(ctx, "project key set is not defined", "project", kn.Project())
		return
	}
	lock.Release()

	// Revoke the key.
	keySet.RevokeKey(kn.Key())
}
