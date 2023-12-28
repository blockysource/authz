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
	createKeyCoreSQL = clearSQL(createKeyCoreSQL)
	insertKeyCoreIdentifierSQL = clearSQL(insertKeyCoreIdentifierSQL)
	getKeyCoreSQL = clearSQL(getKeyCoreSQL)
	getKeyCoreIdentifierSQL = clearSQL(getKeyCoreIdentifierSQL)
	countKeyCoreKeysSQL = clearSQL(countKeyCoreKeysSQL)
	listKeyCoresSQL = clearSQL(listKeyCoresSQL)
	countKeyCoresSQL = clearSQL(countKeyCoresSQL)
	hasMoreKeyCoresSQL = clearSQL(hasMoreKeyCoresSQL)
	deleteKeyCoreIdentifierSQL = clearSQL(deleteKeyCoreIdentifierSQL)
	createKeySQL = clearSQL(createKeySQL)
	insertKeyRevisionIdentifierSQL = clearSQL(insertKeyRevisionIdentifierSQL)
	getKeySQL = clearSQL(getKeySQL)
	getKeyWithSecretSQL = clearSQL(getKeyWithSecretSQL)
	getKeyCoreKeySQL = clearSQL(getKeyCoreKeySQL)
	listKeysSQL = clearSQL(listKeysSQL)
	listKeysWithSecretSQL = clearSQL(listKeysWithSecretSQL)
	listKeyCoreKeysSQL = clearSQL(listKeyCoreKeysSQL)
	countKeysSQL = clearSQL(countKeysSQL)
	updateLatestCoreKeyIdentifierSQL = clearSQL(updateLatestCoreKeyIdentifierSQL)
	revokeKeySQL = clearSQL(revokeKeySQL)
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

// NewKeysStorage creates a new instance of the KeysStorage.
func NewKeysStorage(log *slog.Logger) *KeysStorage {
	return &KeysStorage{
		log: log.With(slog.String("dialect", "postgres")),
	}
}

//go:embed queries/keys/core_create.sql
var createKeyCoreSQL string

// CreateKeyCore creates a new key.
func (k *KeysStorage) CreateKeyCore(ctx context.Context, tx *sql.Tx, key admindriver.KeyCore) error {
	_, err := tx.ExecContext(ctx, createKeyCoreSQL,
		key.ID,
		key.ProjectID,
		key.CreatedAt,
		key.UpdatedAt,
		key.DisplayName,
		key.Algorithm,
		key.RotationInterval.Nanoseconds(),
		key.Priority,
	)
	return err
}

//go:embed queries/keys/core_identifier_insert.sql
var insertKeyCoreIdentifierSQL string

// InsertKeyCoreIdentifier inserts a new key identifier.
func (k *KeysStorage) InsertKeyCoreIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.KeyCoreIdentifier) error {
	_, err := tx.ExecContext(ctx, insertKeyCoreIdentifierSQL,
		identifier.KeyCoreID,
		identifier.ProjectID,
		identifier.Identifier,
	)
	return err
}

//go:embed queries/keys/core_get.sql
var getKeyCoreSQL string

// GetKeyCore gets a key by its identifier.
func (k *KeysStorage) GetKeyCore(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyCoreQuery) (admindriver.KeyCore, error) {
	var key admindriver.KeyCore
	err := tx.QueryRowContext(ctx, getKeyCoreSQL,
		query.ProjectID,
		query.KeyCoreIdentifier,
	).Scan(
		&key.ID,               // id
		&key.ProjectID,        // project_id
		&key.CreatedAt,        // created_at
		&key.UpdatedAt,        // updated_at
		&key.DisplayName,      // display_name
		&key.Algorithm,        // algorithm
		&key.RotationInterval, // rotation_interval
		&key.Priority,         // priority
		&key.DerivedKeysCount, // derived_keys_count
		&key.LastRotatedAt,    // last_rotation
	)
	return key, err
}

// GetAndLockKeyCore gets a key by its identifier and locks it.
func (k *KeysStorage) GetAndLockKeyCore(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyCoreQuery) (admindriver.KeyCore, error) {
	var qb strings.Builder

	qb.WriteString(getKeyCoreSQL)
	qb.WriteString(" FOR UPDATE")

	var key admindriver.KeyCore
	err := tx.QueryRowContext(ctx, qb.String(),
		query.ProjectID,
		query.KeyCoreIdentifier,
	).Scan(
		&key.ID,               // id
		&key.ProjectID,        // project_id
		&key.CreatedAt,        // created_at
		&key.UpdatedAt,        // updated_at
		&key.DisplayName,      // display_name
		&key.Algorithm,        // algorithm
		&key.RotationInterval, // rotation_interval
		&key.Priority,         // priority
		&key.DerivedKeysCount, // revisions
		&key.LastRotatedAt,    // last_rotation
	)
	return key, err
}

//go:embed queries/keys/core_identifier_get.sql
var getKeyCoreIdentifierSQL string

// LookupKeyCoreIdentifier looks up a key identifier.
func (k *KeysStorage) LookupKeyCoreIdentifier(ctx context.Context, tx *sql.Tx, identifier, projectID string) (admindriver.KeyCoreIdentifier, error) {
	var keyIdentifier admindriver.KeyCoreIdentifier
	err := tx.QueryRowContext(ctx, getKeyCoreIdentifierSQL,
		identifier,
		projectID,
	).Scan(
		&keyIdentifier.KeyCoreID,  // core_id
		&keyIdentifier.ProjectID,  // project_id
		&keyIdentifier.Identifier, // identifier
	)
	return keyIdentifier, err
}

//go:embed queries/keys/core_keys_count.sql
var countKeyCoreKeysSQL string

// CountCoreKeys counts the number of keys that matches given query.
func (k *KeysStorage) CountCoreKeys(ctx context.Context, tx *sql.Tx, query admindriver.CountKeyCoreKeysQuery) (int64, error) {
	var total int64
	err := tx.QueryRowContext(ctx, countKeyCoreKeysSQL, query.ProjectID, query.CoreIdentifier).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

//go:embed queries/keys/core_list.sql
var listKeyCoresSQL string

var keyCoreFieldToColumn = map[string]string{
	"name":               "id",
	"uid":                "id",
	"algorithm":          "algorithm",
	"display_name":       "display_name",
	"create_time":        "created_at",
	"update_time":        "updated_at",
	"last_rotated_time":  "last_rotation",
	"rotation_interval":  "rotation_interval",
	"priority":           "priority",
	"derived_keys_count": "derived_keys_count",
}

// ListKeyCores lists keys.
func (k *KeysStorage) ListKeyCores(ctx context.Context, tx *sql.Tx, query admindriver.ListKeyCoresQuery) ([]admindriver.KeyCore, error) {
	var result []admindriver.KeyCore
	var qb strings.Builder
	qb.WriteString(listKeyCoresSQL)
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
			if column, ok := keyCoreFieldToColumn[string(x.Field.Field)]; ok {
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
		var key admindriver.KeyCore
		if err = rows.Scan(
			&key.ID,               // id
			&key.ProjectID,        // project_id
			&key.CreatedAt,        // created_at
			&key.UpdatedAt,        // updated_at
			&key.DisplayName,      // display_name
			&key.Algorithm,        // algorithm
			&key.RotationInterval, // rotation_interval
			&key.Priority,         // priority
			&key.DerivedKeysCount, // derived_keys_count
			&key.LastRotatedAt,    // last_rotation
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

//go:embed queries/keys/core_count.sql
var countKeyCoresSQL string

// CountKeyCores counts the number of keys.
func (k *KeysStorage) CountKeyCores(ctx context.Context, tx *sql.Tx, query admindriver.CountKeyCoresQuery) (int64, error) {
	if query.Filter != nil {
		return 0, status.Error(codes.Unimplemented, "filtering is not implemented yet")
	}

	var total int64
	err := tx.QueryRowContext(ctx, countKeyCoresSQL, query.ProjectID).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

//go:embed queries/keys/core_has_more.sql
var hasMoreKeyCoresSQL string

// HasMoreKeyCores checks if there are more keys.
func (k *KeysStorage) HasMoreKeyCores(ctx context.Context, tx *sql.Tx, query admindriver.HasMoreKeyCoresQuery) (bool, error) {
	var qb strings.Builder
	qb.WriteString(hasMoreKeyCoresSQL)
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
			if column, ok := keyCoreFieldToColumn[string(x.Field.Field)]; ok {
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

// UpdateKeyCore updates a key.
func (k *KeysStorage) UpdateKeyCore(ctx context.Context, tx *sql.Tx, query admindriver.UpdateKeyCoreQuery) error {
	var qb strings.Builder
	qb.WriteString("UPDATE blocky_authz_key_core SET updated_at = $1")
	args := []any{time.Now().Truncate(time.Microsecond)}

	// For each element add a
	for _, elem := range query.Expr.Elements {
		qb.WriteString(", ")

		// No possible traversals, so we can just use the field name
		column, ok := keyCoreFieldToColumn[string(elem.Field.Field)]
		if !ok {
			return fmt.Errorf("no column for field %s", elem.Field.Field)
		}
		qb.WriteString(column)
		qb.WriteString(" = $")
		qb.WriteString(strconv.Itoa(len(args) + 1))

		switch ev := elem.Value.(type) {
		case *expr.ValueExpr:
			// KeyCore does not have map values which could be modified.
			// Only modifiable fields are strings and integers.
			args = append(args, ev.Value)
		default:
			return fmt.Errorf("unsupported update value type %T for column: %s", ev, column)
		}
	}

	qb.WriteString(" WHERE id = (SELECT key_id FROM blocky_authz_key_core_identifier WHERE project_id = $")
	qb.WriteString(strconv.Itoa(len(args) + 1))
	args = append(args, query.ProjectID)
	qb.WriteString(" AND identifier = $")
	qb.WriteString(strconv.Itoa(len(args) + 1))
	args = append(args, query.KeyCoreIdentifier)
	qb.WriteString(")")

	q := qb.String()
	if k.log.Enabled(ctx, slog.LevelDebug) {
		k.log.DebugContext(ctx, "UpdateKeyCore query", q)
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

//go:embed queries/keys/core_identifier_delete.sql
var deleteKeyCoreIdentifierSQL string

// DeleteKeyCoreIdentifier deletes a key identifier.
func (k *KeysStorage) DeleteKeyCoreIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.KeyCoreIdentifier) error {
	// Execute the query
	res, err := tx.ExecContext(ctx, deleteKeyCoreIdentifierSQL,
		identifier.Identifier,
		identifier.KeyCoreID,
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

//go:embed queries/keys/key_create.sql
var createKeySQL string

// CreateKey creates a new key revision.
func (k *KeysStorage) CreateKey(ctx context.Context, tx *sql.Tx, revision admindriver.KeyWithSecret) error {
	_, err := tx.ExecContext(ctx, createKeySQL,
		revision.ID,
		revision.CoreID,
		revision.ProjectID,
		revision.CreatedAt,
		revision.Priority,
		revision.EncryptedSecret,
		revision.Revision,
	)
	return err
}

//go:embed queries/keys/core_key_identifier_insert.sql
var insertKeyRevisionIdentifierSQL string

// InsertCoreKeyIdentifier inserts a new key revision identifier.
func (k *KeysStorage) InsertCoreKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.CoreKeyIdentifier) error {
	_, err := tx.ExecContext(ctx, insertKeyRevisionIdentifierSQL,
		identifier.KeyID,
		identifier.CoreID,
		identifier.Identifier,
	)
	return err
}

//go:embed queries/keys/key_get.sql
var getKeySQL string

// GetKey gets a key revision by its identifier.
func (k *KeysStorage) GetKey(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyQuery) (admindriver.Key, error) {
	var key admindriver.Key
	err := tx.QueryRowContext(ctx, getKeySQL,
		query.ProjectID,
		query.KeyID,
	).Scan(
		&key.ID,        // id
		&key.CoreID,    // key_id
		&key.ProjectID, // project_id
		&key.CreatedAt, // created_at
		&key.RevokedAt, // revoked_at
		&key.Priority,  // priority
		&key.Revision,  // revision
	)
	if err != nil {
		return key, err
	}
	return key, nil
}

//go:embed queries/keys/key_get_with_secret.sql
var getKeyWithSecretSQL string

// GetKeyWithSecret gets a key revision by its identifier.
func (k *KeysStorage) GetKeyWithSecret(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyQuery) (admindriver.KeyWithSecret, error) {
	var key admindriver.KeyWithSecret
	err := tx.QueryRowContext(ctx, getKeyWithSecretSQL,
		query.ProjectID,
		query.KeyID,
	).Scan(
		&key.ID,              // id
		&key.CoreID,          // key_id
		&key.ProjectID,       // project_id
		&key.CreatedAt,       // created_at
		&key.RevokedAt,       // revoked_at
		&key.Priority,        // priority
		&key.Revision,        // revision
		&key.EncryptedSecret, // enc_secret
	)
	if err != nil {
		return key, err
	}
	return key, nil
}

//go:embed queries/keys/core_get_key.sql
var getKeyCoreKeySQL string

// GetKeyCoreKey gets a key core by its identifier.
func (k *KeysStorage) GetKeyCoreKey(ctx context.Context, tx *sql.Tx, query admindriver.GetKeyCoreKeyQuery) (admindriver.Key, error) {
	var key admindriver.Key
	err := tx.QueryRowContext(ctx, getKeyCoreKeySQL,
		query.ProjectID,
		query.CoreIdentifier,
		query.KeyIdentifier,
	).Scan(
		&key.ID,        // id
		&key.CoreID,    // key_id
		&key.ProjectID, // project_id
		&key.CreatedAt, // created_at
		&key.RevokedAt, // revoked_at
		&key.Priority,  // priority
		&key.Revision,  // revision
	)
	if err != nil {
		return key, err
	}
	return key, nil
}

//go:embed queries/keys/key_list.sql
var listKeysSQL string

var keysFieldToColumn = map[string]string{
	"name":            "id",
	"key_id":          "id",
	"create_time":     "created_at",
	"revision_number": "revision",
	"revoked_time":    "revoked_at",
	"priority":        "priority",
}

// ListKeys lists keys.
func (k *KeysStorage) ListKeys(ctx context.Context, tx *sql.Tx, query admindriver.ListKeysQuery) ([]admindriver.Key, error) {
	var qb strings.Builder
	qb.WriteString(listKeysSQL)
	if err := k.listKeysBuildQuery(ctx, tx, query, qb); err != nil {
		return nil, err
	}

	var result []admindriver.Key
	rows, err := tx.QueryContext(ctx, qb.String(), query.ProjectID)
	if err != nil {
		return result, err
	}

	defer rows.Close()

	for rows.Next() {
		var revision admindriver.Key
		if err = rows.Scan(
			&revision.ID,        // id
			&revision.CoreID,    // key_id
			&revision.ProjectID, // project_id
			&revision.CreatedAt, // created_at
			&revision.RevokedAt, // revoked_at
			&revision.Priority,  // priority
			&revision.Revision,  // revision
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

//go:embed queries/keys/key_list_with_secret.sql
var listKeysWithSecretSQL string

// ListKeysWithSecret lists keys.
func (k *KeysStorage) ListKeysWithSecret(ctx context.Context, tx *sql.Tx, query admindriver.ListKeysQuery) ([]admindriver.KeyWithSecret, error) {
	var qb strings.Builder
	qb.WriteString(listKeysWithSecretSQL)
	if err := k.listKeysBuildQuery(ctx, tx, query, qb); err != nil {
		return nil, err
	}

	var result []admindriver.KeyWithSecret
	rows, err := tx.QueryContext(ctx, qb.String(), query.ProjectID)
	if err != nil {
		return result, err
	}

	defer rows.Close()

	for rows.Next() {
		var key admindriver.KeyWithSecret
		if err = rows.Scan(
			&key.ID,              // id
			&key.CoreID,          // key_id
			&key.ProjectID,       // project_id
			&key.CreatedAt,       // created_at
			&key.RevokedAt,       // revoked_at
			&key.Priority,        // priority
			&key.Revision,        // revision
			&key.EncryptedSecret, // enc_secret
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

func (k *KeysStorage) listKeysBuildQuery(ctx context.Context, tx *sql.Tx, query admindriver.ListKeysQuery, qb strings.Builder) error {
	if query.Filter != nil {
		return status.Error(codes.Unimplemented, "filtering is not implemented yet")
	}

	if query.OrderBy != nil && len(query.OrderBy.Fields) > 0 {
		qb.WriteString(" ORDER BY ")
		for i, x := range query.OrderBy.Fields {
			if i > 0 {
				qb.WriteString(", ")
			}

			// No possible traversals, so we can just use the field name
			if column, ok := keysFieldToColumn[string(x.Field.Field)]; ok {
				qb.WriteString(column)
			} else {
				return fmt.Errorf("no column for field %s", x.Field.Field)
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

	return nil
}

//go:embed queries/keys/core_keys_list.sql
var listKeyCoreKeysSQL string

// ListKeyCoreKeys lists keys that matches given query..
func (k *KeysStorage) ListKeyCoreKeys(ctx context.Context, tx *sql.Tx, query admindriver.ListKeyCoreKeysQuery) ([]admindriver.Key, error) {
	var result []admindriver.Key
	var qb strings.Builder
	qb.WriteString(listKeyCoreKeysSQL)

	rows, err := tx.QueryContext(ctx, qb.String(), query.ProjectID, query.CoreIdentifier)
	if err != nil {
		return result, err
	}

	defer rows.Close()

	for rows.Next() {
		var revision admindriver.Key
		if err = rows.Scan(
			&revision.ID,        // id
			&revision.CoreID,    // key_id
			&revision.ProjectID, // project_id
			&revision.CreatedAt, // created_at
			&revision.RevokedAt, // revoked_at
			&revision.Priority,  // priority
			&revision.Revision,  // revision
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

//go:embed queries/keys/key_count.sql
var countKeysSQL string

// CountKeys counts the number of key revisions.
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

//go:embed queries/keys/core_key_update_latest_identifier.sql
var updateLatestCoreKeyIdentifierSQL string

// UpdateLatestCoreKeyIdentifier updates the latest key revision identifier.
func (k *KeysStorage) UpdateLatestCoreKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier admindriver.UpdateLatestCoreKeyIdentifier) error {
	result, err := tx.ExecContext(ctx, updateLatestCoreKeyIdentifierSQL,
		identifier.CoreID,
		identifier.KeyID,
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

//go:embed queries/keys/key_revoke.sql
var revokeKeySQL string

// RevokeKey revokes a key.
func (k *KeysStorage) RevokeKey(ctx context.Context, tx *sql.Tx, query admindriver.RevokeKeyQuery) error {
	res, err := tx.ExecContext(ctx, revokeKeySQL,
		query.ProjectID,
		query.KeyID,
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
