// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package localdb

import (
	"context"
	localdriver "github.com/blockysource/authz/persistence/driver/local"
	localtypes "github.com/blockysource/authz/types/local"
	"gocloud.dev/secrets"
)

// KeysStorage is a storage for keys used for local 'authz' service purpose.
type KeysStorage struct {
	d localdriver.KeysStorage

	secrets *secrets.Keeper
}

// GetKeyQuery is a query structure for the GetKey method.
type GetKeyQuery struct {
	// ProjectID is the project identifier.
	ProjectID string

	// KeyID is the key identifier.
	KeyID string
}

// GetKey gets a single key from the database.
func (s *KeysStorage) GetKey(ctx context.Context, query GetKeyQuery) (localtypes.Key, error) {

}

// ListProjectKeysQuery is a query structure for the ListProjectKeys method,
// that gets all NonRevoked, keys for the given project.
type ListProjectKeysQuery struct {
	// ProjectID is the project identifier.
	ProjectID string
}

// ListProjectKeys lists all keys for the given project.
func (s *KeysStorage) ListProjectKeys(ctx context.Context, query ListProjectKeysQuery) ([]localtypes.Key, error) {

}
