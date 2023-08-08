package admindriverv1

import (
	"context"
	"database/sql"

	admintypesv1 "github.com/blockysource/authz/persistence/admin/v1/types"
)

// KeysStorage is the interface that wraps the methods to manage admin keys.
type KeysStorage interface {
	// CreateKey is a method to create a new Key.
	CreateKey(ctx context.Context, tx *sql.Tx, in admintypesv1.CreateKey) (admintypesv1.Key, error)

	// ListKeys is a method to list all keys that matches given query.
	ListKeys(ctx context.Context, tx *sql.Tx, in admintypesv1.ListKeysQuery) ([]admintypesv1.Key, error)

	// CountKeys is a method to get the total number of keys that matches given query.
	CountKeys(ctx context.Context, tx *sql.Tx, in admintypesv1.ListKeysQuery) (int32, error)
}

