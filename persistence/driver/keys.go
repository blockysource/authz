package admindriver

import (
	"context"
	"database/sql"

	"github.com/blockysource/authz/persistence/types"
)

// KeysStorage is the interface that wraps the methods to manage admin keys.
type KeysStorage interface {
	// CreateKey is a method to create a new Key.
	CreateKey(ctx context.Context, tx *sql.Tx, in typesdb.CreateKey) (typesdb.Key, error)

	// GetNextKeyTableID is a method to get the next key id that
	// that will reserve the id for the next key.
	GetNextKeyTableID(ctx context.Context, tx *sql.Tx) (int32, error)

	// ListKeys is a method to list all keys that matches given query.
	ListKeys(ctx context.Context, tx *sql.Tx, in typesdb.ListKeysQuery) ([]typesdb.Key, error)

	// CountKeys is a method to get the total number of keys that matches given query.
	CountKeys(ctx context.Context, tx *sql.Tx) (int32, error)

	// EstimateCountKeys is a method to get the estimated total number of keys.
	EstimateCountKeys(ctx context.Context, tx *sql.Tx) (int32, error)

	// DeleteKey is a method to delete a key that matches given query.
	DeleteKey(ctx context.Context, tx *sql.Tx, in typesdb.DeleteKey) (bool, error)
}
