package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"golang.org/x/exp/slog"

	admintypesv1 "github.com/blockysource/authz/persistence/admin/v1/types"
	"github.com/blockysource/blockysql"
	"github.com/blockysource/go-pkg/times"
)

// KeysDriverV1 is a postgres implementation of the driver.KeysStorage interface.
type KeysDriverV1 struct {
	db *blockysql.DB

	log *slog.Logger

	clock times.Clock
}

// CreateKey is a method to create a new Key.
func (d *KeysDriverV1) CreateKey(ctx context.Context, tx *sql.Tx, in admintypesv1.CreateKey) (admintypesv1.Key, error) {
	const insertKeyQuery = `INSERT INTO blocky_authz_key (sid, created_at, name, rotation_period)
    VALUES ($1, $2, $3, $4) RETURNING id`
	now := d.clock.Now()
	row := tx.QueryRowContext(ctx, insertKeyQuery,
		in.KeyID,          // sid
		now,               // created_at
		in.DisplayName,    // name
		in.RotationPeriod, // rotation_period
	)

	var id int64
	if err := row.Scan(&id); err != nil {
		// If the constraint was violated, the key with given sid already exists.
		return admintypesv1.Key{}, err
	}

	if in.KeyID == "" {
		// The returned key id would be a string representation of the generated id.
		in.KeyID = strconv.FormatInt(id, 10)

		const updateKeyIDQuery = `UPDATE blocky_authz_key SET sid = $1 WHERE id = $2`
		if _, err := tx.ExecContext(ctx, updateKeyIDQuery, in.KeyID, id); err != nil {
			return admintypesv1.Key{}, err
		}
	}

	// Insert the key algorithms.
	const insertKeyAlgorithmsQuery = `INSERT INTO blocky_authz_key_algorithm (key_id, signing_algorithm)`

	var sb strings.Builder
	sb.WriteString(insertKeyAlgorithmsQuery)
	for i := range in.SigningAlgorithms {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("($")
		sb.WriteString(strconv.Itoa(i*2 + 1)) // $1
		sb.WriteString(", $")
		sb.WriteString(strconv.Itoa(i*2 + 2)) // $2
		sb.WriteRune(')')
	}

	// The values for each algorithm is a pair of (key_id, algorithm).
	values := make([]any, 0, len(in.SigningAlgorithms)*2)
	for _, algorithm := range in.SigningAlgorithms {
		values = append(values, id, algorithm)
	}

	if _, err := tx.ExecContext(ctx, sb.String(), values...); err != nil {
		return admintypesv1.Key{}, err
	}

	out := admintypesv1.Key{
		KeyID:          in.KeyID,
		CreatedAt:      now,
		DisplayName:    in.DisplayName,
		RotationPeriod: in.RotationPeriod,
		Algorithms:     in.SigningAlgorithms,
	}

	return out, nil
}

func (d *KeysDriverV1) ListKeys(ctx context.Context, tx *sql.Tx, in admintypesv1.ListKeysQuery) ([]admintypesv1.Key, error) {
	var keys []admintypesv1.Key

	const selectKeysQuery = `SELECT     
    k.sid AS sid, 
    k.created_at AS created_at, 
    k.name AS name, 
    k.rotation_period AS rotation_period,
    k.priority AS priority,
    k.versions AS versions,
    k.active AS active,

    ka.algorithms AS algorithms
FROM blocky_authz_key AS k
LEFT JOIN LATERAL (
    SELECT array_agg(ka.signing_algorithm) AS algorithms
    FROM blocky_authz_key_algorithm AS ka
    WHERE ka.key_id = k.id
) AS ka ON TRUE`

	var sb strings.Builder
	sb.WriteString(selectKeysQuery)

	if in.PageSize > 0 {
		sb.WriteString(" LIMIT ")
		sb.WriteString(strconv.Itoa(int(in.PageSize)))
	}

	if in.Offset > 0 {
		sb.WriteString(" OFFSET ")
		sb.WriteString(strconv.Itoa(int(in.Offset)))
	}

	rows, err := tx.QueryContext(ctx, sb.String())
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var key admintypesv1.Key
		var algArr AlgorithmsArray
		if err := rows.Scan(
			&key.KeyID,
			&key.CreatedAt,
			&key.DisplayName,
			&key.RotationPeriod,
			&key.Priority,
			&key.Versions,
			&algArr,
		); err != nil {
			return nil, err
		}
		key.Algorithms = algArr
		keys = append(keys, key)
	}
	return keys, nil
}
