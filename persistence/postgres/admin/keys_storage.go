// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package postgresadmin

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	admindriver "github.com/blockysource/authz/persistence/driver/admin"
	"github.com/blockysource/blocky-aip/expr"
)

func init() {
	createKeySQL = clearSQL(createKeySQL)
	insertKeyIdentifierSQL = clearSQL(insertKeyIdentifierSQL)
	getKeySQL = clearSQL(getKeySQL)
	getKeyIdentifierSQL = clearSQL(getKeyIdentifierSQL)
	listKeysSQL = clearSQL(listKeysSQL)
	countKeysSQL = clearSQL(countKeysSQL)
	hasMoreKeysSQL = clearSQL(hasMoreKeysSQL)
	deleteKeyIdentifierSQL = clearSQL(deleteKeyIdentifierSQL)
	createKeyRevisionSQL = clearSQL(createKeyRevisionSQL)
	insertKeyRevisionIdentifierSQL = clearSQL(insertKeyRevisionIdentifierSQL)
	getKeyRevisionSQL = clearSQL(getKeyRevisionSQL)
	getFullKeyRevisionSQL = clearSQL(getFullKeyRevisionSQL)
	listKeyRevisionsSQL = clearSQL(listKeyRevisionsSQL)
	countKeyRevisionsSQL = clearSQL(countKeyRevisionsSQL)
	updateLatestKeyRevisionIdentifierSQL = clearSQL(updateLatestKeyRevisionIdentifierSQL)
	revokeKeyRevisionSQL = clearSQL(revokeKeyRevisionSQL)
}

const copyright = `-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1
`

func clearSQL(inSQL string) string {
	// trim the license header
	return strings.TrimPrefix(inSQL, copyright)
}

var _ admindriver.KeysStorage = (*KeysStorage)(nil)

// KeysStorage is an implementation of the admindriver.KeysStorage interface.
type KeysStorage struct {
	log *slog.Logger
}

//go:embed queries/keys/key_create.sql
var createKeySQL string

// CreateKey creates a new key.
func (k *KeysStorage) CreateKey(ctx context.Context, tx *sql.Tx, key admindriver.Key) error {
	_, err := tx.ExecContext(ctx, createKeySQL,
		key.ID,
		key.ProjectID,
		key.CreatedAt,
		key.UpdatedAt,
		key.DisplayName,
		key.Algorithm,
		key.RotationPeriod.Nanoseconds(),
		key.Priority,
	)
	return err
}

//go:embed queries/keys/key_identifier_insert.sql
var insertKeyIdentifierSQL string

// InsertKeyIdentifier inserts a new key identifier.
func (k *KeysStorage) InsertKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.KeyIdentifier) error {
	_, err := tx.ExecContext(ctx, insertKeyIdentifierSQL,
		identifier.KeyID,
		identifier.ProjectID,
		identifier.Identifier,
	)
	return err
}

//go:embed queries/keys/key_get.sql
var getKeySQL string

// GetKey gets a key by its identifier.
func (k *KeysStorage) GetKey(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyQuery) (admindriver.Key, error) {
	var key admindriver.Key
	err := tx.QueryRowContext(ctx, getKeySQL,
		query.ProjectID,
		query.KeyIdentifier,
	).Scan(
		&key.ID,             // id
		&key.ProjectID,      // project_id
		&key.CreatedAt,      // created_at
		&key.UpdatedAt,      // updated_at
		&key.DisplayName,    // display_name
		&key.Algorithm,      // algorithm
		&key.RotationPeriod, // rotation_period
		&key.Priority,       // priority
		&key.Revisions,      // revisions
		&key.LastRotatedAt,  // last_rotation
	)
	return key, err
}

// GetAndLockKey gets a key by its identifier and locks it.
func (k *KeysStorage) GetAndLockKey(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyQuery) (admindriver.Key, error) {
	var qb strings.Builder

	qb.WriteString(getKeySQL)
	qb.WriteString(" FOR UPDATE")

	var key admindriver.Key
	err := tx.QueryRowContext(ctx, qb.String(),
		query.ProjectID,
		query.KeyIdentifier,
	).Scan(
		&key.ID,             // id
		&key.ProjectID,      // project_id
		&key.CreatedAt,      // created_at
		&key.UpdatedAt,      // updated_at
		&key.DisplayName,    // display_name
		&key.Algorithm,      // algorithm
		&key.RotationPeriod, // rotation_period
		&key.Priority,       // priority
		&key.Revisions,      // revisions
		&key.LastRotatedAt,  // last_rotation
	)
	return key, err
}

//go:embed queries/keys/key_identifier_get.sql
var getKeyIdentifierSQL string

// LookupKeyIdentifier looks up a key identifier.
func (k *KeysStorage) LookupKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier, projectID string) (admindriver.KeyIdentifier, error) {
	var keyIdentifier admindriver.KeyIdentifier
	err := tx.QueryRowContext(ctx, getKeyIdentifierSQL,
		identifier,
		projectID,
	).Scan(
		&keyIdentifier.KeyID,      // key_id
		&keyIdentifier.ProjectID,  // project_id
		&keyIdentifier.Identifier, // identifier
	)
	return keyIdentifier, err
}

//go:embed queries/keys/key_list.sql
var listKeysSQL string

var keysFieldToColumn = map[string]string{
	"name":              "id",
	"uid":               "id",
	"algorithm":         "algorithm",
	"display_name":      "display_name",
	"create_time":       "created_at",
	"update_time":       "updated_at",
	"last_rotated_time": "last_rotation",
	"rotation_period":   "rotation_period",
	"priority":          "priority",
	"revisions":         "revisions",
}

// ListKeys lists keys.
func (k *KeysStorage) ListKeys(ctx context.Context, tx *sql.Tx, query admindriver.ListKeysQuery) ([]admindriver.Key, error) {
	var result []admindriver.Key
	var qb strings.Builder
	qb.WriteString(listKeysSQL)
	if query.Filter != nil {
		return result, status.Error(codes.Unimplemented, "filtering is not implemented yet")
	}

	if query.OrderBy != nil {
		qb.WriteString(" ORDER BY ")
		for i, x := range query.OrderBy.Fields {
			if i > 0 {
				qb.WriteString(", ")
			}

			// No possible traversals, so we can just use the field name
			if column, ok := keysFieldToColumn[string(x.Field.Field)]; ok {
				qb.WriteString(column)
			} else {
				return result, fmt.Errorf("no column for field %s", x.Field.Field)
			}

			if x.Order == expr.DESC {
				qb.WriteString(" DESC")
			}
		}
	}

	if query.PageSize > 0 {
		qb.WriteString(fmt.Sprintf(" LIMIT %d", query.PageSize))
	}

	if query.Skip > 0 {
		qb.WriteString(fmt.Sprintf(" OFFSET %d", query.Skip))
	}

	rows, err := tx.QueryContext(ctx, qb.String(), query.ProjectID)
	if err != nil {
		return result, err
	}
	defer rows.Close()

	for rows.Next() {
		var key admindriver.Key
		if err = rows.Scan(
			&key.ID,             // id
			&key.ProjectID,      // project_id
			&key.CreatedAt,      // created_at
			&key.UpdatedAt,      // updated_at
			&key.DisplayName,    // display_name
			&key.Algorithm,      // algorithm
			&key.RotationPeriod, // rotation_period
			&key.Priority,       // priority
			&key.Revisions,      // revisions
			&key.LastRotatedAt,  // last_rotation
		); err != nil {
			return result, err
		}

		result = append(result, key)
	}

	if err = rows.Err(); err != nil {
		return result, err
	}

	return result, nil
}

//go:embed queries/keys/key_count.sql
var countKeysSQL string

// CountKeys counts the number of keys.
func (k *KeysStorage) CountKeys(ctx context.Context, tx *sql.Tx, query admindriver.CountKeysQuery) (int64, error) {
	if query.Filter != nil {
		return 0, status.Error(codes.Unimplemented, "filtering is not implemented yet")
	}

	var total int64
	err := tx.QueryRowContext(ctx, countKeysSQL, query.ProjectID).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

//go:embed queries/keys/key_has_more.sql
var hasMoreKeysSQL string

// HasMoreKeys checks if there are more keys.
func (k *KeysStorage) HasMoreKeys(ctx context.Context, tx *sql.Tx, query admindriver.HasMoreKeysQuery) (bool, error) {
	var qb strings.Builder
	qb.WriteString(hasMoreKeysSQL)
	if query.Filter != nil {
		return false, status.Error(codes.Unimplemented, "filtering is not implemented yet")
	}

	if query.OrderBy != nil {
		qb.WriteString(" ORDER BY ")
		for i, x := range query.OrderBy.Fields {
			if i > 0 {
				qb.WriteString(", ")
			}

			// No possible traversals, so we can just use the field name
			if column, ok := keysFieldToColumn[string(x.Field.Field)]; ok {
				qb.WriteString(column)
			} else {
				return false, fmt.Errorf("no column for field %s", x.Field.Field)
			}

			if x.Order == expr.DESC {
				qb.WriteString(" DESC")
			}
		}
	}
	// Always limit to 1
	qb.WriteString(" LIMIT 1")

	var i int
	err := tx.QueryRowContext(ctx, qb.String(), query.ProjectID, query.LastCreatedAt).
		Scan(&i)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// UpdateKey updates a key.
func (k *KeysStorage) UpdateKey(ctx context.Context, tx *sql.Tx, query admindriver.UpdateKeyQuery) error {
	var qb strings.Builder
	qb.WriteString("UPDATE blocky_authz_key SET updated_at = $1")
	args := []any{time.Now().Truncate(time.Microsecond)}

	// For each element add a
	for _, elem := range query.Expr.Elements {
		qb.WriteString(", ")

		// No possible traversals, so we can just use the field name
		column, ok := keysFieldToColumn[string(elem.Field.Field)]
		if !ok {
			return fmt.Errorf("no column for field %s", elem.Field.Field)
		}
		qb.WriteString(column)
		qb.WriteString(" = $")
		qb.WriteString(strconv.Itoa(len(args) + 1))

		switch ev := elem.Value.(type) {
		case *expr.ValueExpr:
			// Key does not have map values which could be modified.
			// Only modifiable fields are strings and integers.
			args = append(args, ev.Value)
		default:
			return fmt.Errorf("unsupported update value type %T for column: %s", ev, column)
		}
	}

	qb.WriteString(" WHERE id = (SELECT key_id FROM blocky_authz_key_identifier WHERE project_id = $")
	qb.WriteString(strconv.Itoa(len(args) + 1))
	args = append(args, query.ProjectID)
	qb.WriteString(" AND identifier = $")
	qb.WriteString(strconv.Itoa(len(args) + 1))
	args = append(args, query.KeyIdentifier)
	qb.WriteString(")")

	q := qb.String()
	if k.log.Enabled(ctx, slog.LevelDebug) {
		k.log.DebugContext(ctx, "UpdateKey query", q)
	}

	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	ra, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if ra == 0 {
		return sql.ErrNoRows
	}
	return err
}

//go:embed queries/keys/key_identifier_delete.sql
var deleteKeyIdentifierSQL string

// DeleteKeyIdentifier deletes a key identifier.
func (k *KeysStorage) DeleteKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.KeyIdentifier) error {
	// Execute the query
	res, err := tx.ExecContext(ctx, deleteKeyIdentifierSQL,
		identifier.Identifier,
		identifier.KeyID,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

//go:embed queries/keys/key_revision_create.sql
var createKeyRevisionSQL string

// CreateKeyRevision creates a new key revision.
func (k *KeysStorage) CreateKeyRevision(ctx context.Context, tx *sql.Tx, revision admindriver.KeyRevision) error {
	_, err := tx.ExecContext(ctx, createKeyRevisionSQL,
		revision.ID,
		revision.KeyID,
		revision.ProjectID,
		revision.CreatedAt,
		revision.Priority,
		revision.EncryptedSecret,
		revision.Revision,
	)
	return err
}

//go:embed queries/keys/key_revision_identifier_insert.sql
var insertKeyRevisionIdentifierSQL string

// InsertKeyRevisionIdentifier inserts a new key revision identifier.
func (k *KeysStorage) InsertKeyRevisionIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.KeyRevisionIdentifier) error {
	_, err := tx.ExecContext(ctx, insertKeyRevisionIdentifierSQL,
		identifier.KeyRevisionID,
		identifier.KeyID,
		identifier.Identifier,
	)
	return err
}

//go:embed queries/keys/key_revision_get.sql
var getKeyRevisionSQL string

// GetKeyRevision gets a key revision by its identifier.
func (k *KeysStorage) GetKeyRevision(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyRevisionQuery) (admindriver.KeyRevision, error) {
	var revision admindriver.KeyRevision
	err := tx.QueryRowContext(ctx, getKeyRevisionSQL,
		query.KeyRevisionIdentifier,
		query.KeyIdentifier,
	).Scan(
		&revision.ID,        // id
		&revision.KeyID,     // key_id
		&revision.ProjectID, // project_id
		&revision.CreatedAt, // created_at
		&revision.RevokedAt, // revoked_at
		&revision.Priority,  // priority
		&revision.Revision,  // revision
	)
	if err != nil {
		return revision, err
	}
	return revision, nil
}

//go:embed queries/keys/key_revision_get_full.sql
var getFullKeyRevisionSQL string

// GetFullKeyRevision gets a key revision by its identifier.
func (k *KeysStorage) GetFullKeyRevision(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyRevisionQuery) (admindriver.KeyRevision, error) {
	var revision admindriver.KeyRevision
	err := tx.QueryRowContext(ctx, getFullKeyRevisionSQL,
		query.KeyRevisionIdentifier,
		query.KeyIdentifier,
	).Scan(
		&revision.ID,              // id
		&revision.KeyID,           // key_id
		&revision.ProjectID,       // project_id
		&revision.CreatedAt,       // created_at
		&revision.RevokedAt,       // revoked_at
		&revision.Priority,        // priority
		&revision.Revision,        // revision
		&revision.EncryptedSecret, // enc_secret
	)
	if err != nil {
		return revision, err
	}
	return revision, nil
}

//go:embed queries/keys/key_revision_list.sql
var listKeyRevisionsSQL string

var keyRevisionFieldToColumn = map[string]string{
	"name":            "id",
	"kid":             "id",
	"create_time":     "created_at",
	"revision_number": "revision",
	"revoked_time":    "revoked_at",
	"priority":        "priority",
}

// ListKeyRevisions lists key revisions.
func (k *KeysStorage) ListKeyRevisions(ctx context.Context, tx *sql.Tx, query admindriver.ListKeyRevisionsQuery) ([]admindriver.KeyRevision, error) {
	var result []admindriver.KeyRevision
	var qb strings.Builder
	qb.WriteString(listKeyRevisionsSQL)
	if query.Filter != nil {
		return result, status.Error(codes.Unimplemented, "filtering is not implemented yet")
	}

	if query.OrderBy != nil && len(query.OrderBy.Fields) > 0 {
		qb.WriteString(" ORDER BY ")
		for i, x := range query.OrderBy.Fields {
			if i > 0 {
				qb.WriteString(", ")
			}

			// No possible traversals, so we can just use the field name
			if column, ok := keyRevisionFieldToColumn[string(x.Field.Field)]; ok {
				qb.WriteString(column)
			} else {
				return result, fmt.Errorf("no column for field %s", x.Field.Field)
			}

			if x.Order == expr.DESC {
				qb.WriteString(" DESC")
			}
		}
	}

	if query.PageSize > 0 {
		qb.WriteString(fmt.Sprintf(" LIMIT %d", query.PageSize))
	}

	if query.Skip > 0 {
		qb.WriteString(fmt.Sprintf(" OFFSET %d", query.Skip))
	}

	rows, err := tx.QueryContext(ctx, qb.String(), query.ProjectID, query.KeyIdentifier)
	if err != nil {
		return result, err
	}

	defer rows.Close()

	for rows.Next() {
		var revision admindriver.KeyRevision
		if err = rows.Scan(
			&revision.ID,              // id
			&revision.KeyID,           // key_id
			&revision.ProjectID,       // project_id
			&revision.CreatedAt,       // created_at
			&revision.RevokedAt,       // revoked_at
			&revision.Priority,        // priority
			&revision.EncryptedSecret, // enc_secret
			&revision.Revision,        // revision
		); err != nil {
			return result, err
		}

		result = append(result, revision)
	}

	if err = rows.Err(); err != nil {
		return result, err
	}

	return result, nil
}

//go:embed queries/keys/key_revision_count.sql
var countKeyRevisionsSQL string

// CountKeyRevisions counts the number of key revisions.
func (k *KeysStorage) CountKeyRevisions(ctx context.Context, tx *sql.Tx, query admindriver.CountKeyRevisionsQuery) (int64, error) {
	if query.Filter != nil {
		return 0, status.Error(codes.Unimplemented, "filtering is not implemented yet")
	}

	var total int64
	err := tx.QueryRowContext(ctx, countKeyRevisionsSQL, query.ProjectID, query.KeyIdentifier).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

//go:embed queries/keys/key_revision_update_latest_identifier.sql
var updateLatestKeyRevisionIdentifierSQL string

// UpdateLatestKeyRevisionIdentifier updates the latest key revision identifier.
func (k *KeysStorage) UpdateLatestKeyRevisionIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.UpdateLatestKeyRevisionIdentifier) error {
	result, err := tx.ExecContext(ctx, updateLatestKeyRevisionIdentifierSQL,
		identifier.KeyID,
		identifier.KeyRevisionID,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

//go:embed queries/keys/key_revision_revoke.sql
var revokeKeyRevisionSQL string

// RevokeKeyRevision revokes a key revision.
func (k *KeysStorage) RevokeKeyRevision(ctx context.Context, tx *sql.Tx, query admindriver.RevokeKeyRevisionQuery) error {
	res, err := tx.ExecContext(ctx, revokeKeyRevisionSQL,
		query.ProjectID,
		query.KeyIdentifier,
		query.RevisionIdentifier,
		query.RevokedAt,
	)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}
