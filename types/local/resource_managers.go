// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package localtypes

import (
	"time"

	"github.com/google/uuid"

	"github.com/blockysource/authz/types/algorithm"
)

// ResourceManager represents a resource manager stored in the database.
type ResourceManager struct {
	// ID is the unique identifier of the resource manager.
	ID uuid.UUID

	// CreatedAt is the time when the resource manager was created.
	CreatedAt time.Time

	// Audience is the audience of the resource manager.
	Audience string

	// SigningAlgorithms are the algorithms that this resource manager supports.
	SigningAlgorithms []algorithm.SigningAlgorithm
}

// ResourcePermissionScope represents a resource permission scope stored in the database.
type ResourcePermissionScope struct {
	// ID is the unique identifier of the resource permission.
	ID uuid.UUID

	// ManagerID is the unique identifier of the resource manager.
	ManagerID uuid.UUID

	// Scope is the scope of the resource permission.
	Scope string
}
