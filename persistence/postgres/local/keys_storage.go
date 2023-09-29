// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package postgreslocal

import (
	"context"
	"database/sql"
	_ "embed"
	"log/slog"

	localdriver "github.com/blockysource/authz/persistence/driver/local"
	"github.com/blockysource/authz/persistence/internal/purge"
)

func init() {
	keysListValidSQL = purge.SanitizeSQL(keysListValidSQL)
}

// KeysStorage is a postgres keys storage used for local 'authz' service purpose.
type KeysStorage struct {
	log *slog.Logger
}

//go:embed queries/keys/keys_list_valid.sql
var keysListValidSQL string

// ListValidKeys returns a list of valid keys.
func (s *KeysStorage) ListValidKeys(ctx context.Context, tx *sql.Tx, projectID string) ([]localdriver.Key, error) {
	rows, err := tx.QueryContext(ctx, keysListValidSQL, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []localdriver.Key
	for rows.Next() {
		var k localdriver.Key
		err = rows.Scan(
			&k.RevisionID,
			&k.KeyID,
			&k.ProjectID,
			&k.Algorithm,
			&k.Priority,
			&k.EncSecret,
			&k.Revision,
		)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}

	return keys, nil
}
