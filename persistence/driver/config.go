package admindriver

import (
	"context"
	"database/sql"

	"github.com/blockysource/authz/persistence/types"
)

// ConfigStorage is the interface that wraps the methods to manage the service config.
type ConfigStorage interface {
	// UpsertServiceConfig is a method to create or update a service config.
	// This assumes that the values in the input are already validated,
	// and all unprovided values are set to their default values.
	UpsertServiceConfig(ctx context.Context, tx *sql.Tx, in typesdb.UpsertServiceConfig) (typesdb.ServiceConfig, error)

	// GetServiceConfig is a method to get the service config from the storage.
	GetServiceConfig(ctx context.Context, tx *sql.Tx) (typesdb.ServiceConfig, error)
}

