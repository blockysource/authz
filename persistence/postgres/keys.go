package postgresdriver

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/exp/slog"

	"github.com/blockysource/authz/persistence/types"
	"github.com/blockysource/blockysql"
	"github.com/blockysource/go-pkg/times"
)

// KeysStorage is a postgres implementation of the driver.KeysStorage interface.
type KeysStorage struct {
	db *blockysql.DB

	log *slog.Logger

	clock times.Clock
}

//go:embed queries/keys_insert.sql
//
// This is embedded insert key query that is used to create a new key.
// It requires the following parameters in order:
// - sid
// - created_at
// - display_name
// - active
// - rotation_period
// - priority
// Returns the id of the created key.
var insertKeyQuery string

//go:embed queries/keys_alg_insert_base.sql
//
// This is embedded insert key algorithm query that is used to create a new key algorithm.
// This needs to be used either for a single or batch insert.
// Depending on the number of algorithms to be inserted, the query needs to be appended with the following:
// - (key_id, signing_algorithm), ($2n+1, $2n+2), where n is the number of algorithms to be inserted (starting from 0).
var insertKeyAlgorithmBaseQuery string

//go:embed queries/keys_insert_with_table_id.sql
//
// This is embedded insert key query that is used to create a new key.
// It requires the table id to be reserved in previous query.
// It requires the following parameters in order:
// - id
// - sid
// - created_at
// - display_name
// - active
// - rotation_period
// - priority
var insertKeyWithTableIDQuery string

// CreateKey is a method to create a new Key.
func (s *KeysStorage) CreateKey(ctx context.Context, tx *sql.Tx, in typesdb.CreateKey) (typesdb.Key, error) {
	if in.TableID == 0 {
		row := tx.QueryRowContext(ctx, insertKeyQuery,
			in.KeyID,          // sid
			in.CreateTime,               // created_at
			in.DisplayName,    // display_name
			in.Active,         // active
			in.RotationPeriod, // rotation_period
			in.Priority,       // priority
		)

		if err := row.Scan(&in.TableID); err != nil {
			// If the constraint was violated, the key with given sid already exists.
			return typesdb.Key{}, err
		}
	} else {
		_, err := tx.ExecContext(ctx, insertKeyWithTableIDQuery,
			in.TableID,        // id
			in.KeyID,          // sid
			in.CreateTime,               // created_at
			in.DisplayName,    // display_name
			in.Active,         // active
			in.RotationPeriod, // rotation_period
			in.Priority,       // priority
		)
		if err != nil {
			return typesdb.Key{}, err
		}
	}

	// Insert the key algorithms.
	insertKeyAlgorithmsQuery := s.buildInsertKeyAlgorithmsQuery(len(in.SigningAlgorithms))

	// The values for each algorithm is a pair of (key_id, algorithm).
	values := make([]any, 0, len(in.SigningAlgorithms)*2)
	for _, algorithm := range in.SigningAlgorithms {
		values = append(values,
			in.TableID,        // key_id
			algorithm, // signing_algorithm
		)
	}

	// Execute the query.
	if _, err := tx.ExecContext(ctx, insertKeyAlgorithmsQuery, values...); err != nil {
		return typesdb.Key{}, err
	}

	// Prepare the output key.
	out := typesdb.Key{
		TableID:        in.TableID,
		KeyID:          in.KeyID,
		CreatedAt:      in.CreateTime,
		DisplayName:    in.DisplayName,
		RotationPeriod: in.RotationPeriod,
		Algorithms:     in.SigningAlgorithms,
		Priority:       in.Priority,
		Active:         in.Active,
	}

	return out, nil
}

//go:embed queries/keys_get_next_table_id.sql
// This is embedded get next table id query that increments the key id sequence.
// It requires no parameters.
// Advances the sequence and returns the next value.
var keysNextTableIDQuery string

// GetNextKeyTableID returns the next key table id.
// It implements the admindriver.KeysStorage interface.
func (s *KeysStorage) GetNextKeyTableID(ctx context.Context, tx *sql.Tx) (int32, error) {
	var id int32
	row := tx.QueryRowContext(ctx, keysNextTableIDQuery)
	if err := row.Scan(&id); err != nil {
		return 0, err
	}

	return id, nil
}

func (s *KeysStorage) buildInsertKeyAlgorithmsQuery(algLen int) string {
	var sb strings.Builder
	sb.WriteString(insertKeyAlgorithmBaseQuery)
	for i := 0; i < algLen; i += 2 {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("($")
		sb.WriteString(strconv.Itoa(i + 1)) // $1
		sb.WriteString(", $")
		sb.WriteString(strconv.Itoa(i + 2)) // $2
		sb.WriteRune(')')
	}

	return sb.String()
}

//go:embed queries/keys_list.sql
//
// This is embedded list keys query that is used to list keys.
// It requires the following parameters in order:
// Returned columns:
// - id
// - sid
// - created_at
// - display_name
// - rotation_period
// - priority
// - versions
// - active
// - signing_algorithms
var listKeysQuery string

// ListKeys returns the list of keys that matches given query.
// It implements the admindriver.KeysStorage interface.
func (s *KeysStorage) ListKeys(ctx context.Context, tx *sql.Tx, in typesdb.ListKeysQuery) ([]typesdb.Key, error) {
	var keys []typesdb.Key

	var sb strings.Builder
	sb.WriteString(listKeysQuery)

	if len(in.Filters) != 0 {

	}

	if len(in.Order) != 0 {
		sb.WriteString(" ORDER BY ")

		for i, o := range in.Order {
			if i != 0 {
				sb.WriteString(", ")
			}

			column, err := s.keyColumnName(o.FieldName)
			if err != nil {
				return nil, err
			}
			sb.WriteString(column)


			if o.Descending {
				sb.WriteString(" DESC")
			}

			switch o.Nulls {
			case typesdb.NullsFirst:
				sb.WriteString(" NULLS FIRST")
			case typesdb.NullsLast:
				sb.WriteString(" NULLS LAST")
			}
		}
	}

	var args []any
	if in.PageSize != 0 {
		sb.WriteString(" LIMIT $1")
		args = append(args, in.PageSize)
	}

	if in.Offset != 0 {
		sb.WriteString(" OFFSET $2")
		args = append(args, in.Offset)
	}

	// Query the keys using listKeysQuery embedded in queries/list_keys.sql.
	rows, err := tx.QueryContext(ctx, sb.String(), args)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var key typesdb.Key
		var algArr AlgorithmsArray
		err = rows.Scan(
			&key.TableID,
			&key.KeyID,
			&key.CreatedAt,
			&key.DisplayName,
			&key.RotationPeriod,
			&key.Priority,
			&key.Versions,
			&key.Active,
			&algArr,
		)
		if err != nil {
			return nil, err
		}
		key.Algorithms = algArr
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *KeysStorage) keyColumnName(fieldName string) (string, error) {
	switch fieldName {
	case typesdb.KeyFieldTableID:
		return "id", nil
	case typesdb.KeyFieldKeyID:
		return "sid", nil
	case typesdb.KeyFieldCreatedAt:
		return "created_at", nil
	case typesdb.KeyFieldDisplayName:
		return "display_name", nil
	case typesdb.KeyFieldRotationPeriod:
		return "rotation_period", nil
	case typesdb.KeyFieldAlgorithms:
		return "signing_algorithms", nil
	case typesdb.KeyFieldPriority:
		return "priority", nil
	case typesdb.KeyFieldActive:
		return "active", nil
	case typesdb.KeyFieldLastRotatedAt:
		return "last_rotated_at", nil
	case typesdb.KeyFieldRevokedAt:
		return "revoked_at", nil
	case typesdb.KeyFieldVersions:
		return "versions", nil
	}
	return "", fmt.Errorf("unknown key field name: %s", fieldName)
}

//go:embed queries/keys_count.sql
//
// This is embedded count keys query that is used to get the total number of keys that matches given query.
// Returns a single integer value that represents the total number of keys.
var keysCountQuery string

//go:embed queries/keys_estimate_count.sql
//
// This is embedded estimate count keys query that is used to get the total number of keys that matches given query.
// Returns a single integer value that represents the estimated number of keys.
var keysEstimateCountQuery string

// CountKeys is a method to get the total number of keys that matches given query.
// Implements admindriver.KeysStorage interface.
func (s *KeysStorage) CountKeys(ctx context.Context, tx *sql.Tx) (int32, error) {
	var total int32
	row := tx.QueryRowContext(ctx, keysCountQuery)
	err := row.Scan(&total)
	if err != nil {
		return 0, err
	}

	return total, nil
}

// EstimateCountKeys is a method to get the estimated total number of keys that matches given query.
// Implements admindriver.KeysStorage interface.
func (s *KeysStorage) EstimateCountKeys(ctx context.Context, tx *sql.Tx) (int32, error) {
	var total int32
	row := tx.QueryRowContext(ctx, keysEstimateCountQuery)
	err := row.Scan(&total)
	if err != nil {
		return 0, err
	}

	return total, nil
}

//go:embed queries/keys_alg_delete.sql
// This is embedded delete key algorithms query that is used to delete key algorithms.
// It requires the following parameters in order:
// - key_id
var deleteKeyAlgorithmsQuery string

//go:embed queries/keys_delete.sql
// This is embedded delete key query that is used to delete a key.
// It requires the following parameters in order:
// - sid
var deleteKeyQuery string

// DeleteKey is a method to delete a key.
func (s *KeysStorage) DeleteKey(ctx context.Context, tx *sql.Tx, in typesdb.DeleteKey) (bool, error) {
	// Delete key algorithms.
	_, err := tx.ExecContext(ctx, deleteKeyAlgorithmsQuery, in.KeyID)
	if err != nil {
		return false, err
	}

	// Delete key.
	var result sql.Result
	result, err = tx.ExecContext(ctx, deleteKeyQuery, in.KeyID)
	if err != nil {
		return false, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rowsAffected > 0, nil
}

//go:embed queries/keys_update_sid.sql
// This is embedded update key sid query that is used to update the sid of a key.
// It requires the following parameters in order:
// - sid (new sid)
// - id (key id int)
var updateKeySIDQuery string

// SetKeyID is a method to set the key id for a key.
// It implements the admindriver.KeysStorage interface.
func (s *KeysStorage) SetKeyID(ctx context.Context, tx *sql.Tx, keyID string) error {
	result, err := tx.ExecContext(ctx, updateKeySIDQuery, keyID, keyID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		// This is a default error returned by sql package when no rows are affected.
		return sql.ErrNoRows
	}

	return nil
}
