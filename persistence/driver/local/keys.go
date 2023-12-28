// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package localdriver

import (
	"context"
	"database/sql"

	"github.com/blockysource/authz/persistence/driver/algorithmdb"
)

// KeysStorage is a storage for keys used for local 'authz' service purpose.
// This API can break at any time without notice.
type KeysStorage interface {
	// ListValidKeys returns a list of valid keys.
	ListValidKeys(ctx context.Context, tx *sql.Tx, projectID string) ([]Key, error)
}

// Key represents a valid signing / verification key used by the service.
type Key struct {
	// RevisionID is the key revision identifier.
	RevisionID string

	// KeyID is the key identifier.
	KeyID string

	// ProjectID is the project identifier.
	ProjectID string

	// Priority is the key priority.
	Priority int

	// Algorithm is the key algorithm.
	Algorithm algorithmdb.SigningAlgorithm

	// EncSecret is the key secret.
	EncSecret []byte

	// Revision is the key revision number.
	Revision int
}
