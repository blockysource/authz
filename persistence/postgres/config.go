package postgresdriver

import (
	"context"
	"database/sql"
	"time"

	"github.com/blockysource/authz/persistence/types"
	"github.com/blockysource/blockysql"
	"github.com/blockysource/go-pkg/times"
)

// ConfigStorage is an implementation of the driver.ConfigStorage interface.
type ConfigStorage struct {
	db *blockysql.DB

	time times.Clock
}

// UpsertServiceConfig is a method to upsert the service configuration.
func (s *ConfigStorage) UpsertServiceConfig(ctx context.Context, tx *sql.Tx, in typesdb.UpsertServiceConfig) (typesdb.ServiceConfig, error) {
	var defaultKeyID sql.NullInt32

	// If the default key identifier is not empty, get the key identifier of the default key.
	if in.DefaultKeyID != "" {
		const selectDefaultKeyIDQuery = `SELECT id FROM blocky_authz_key WHERE sid = $1`

		row := tx.QueryRowContext(ctx, selectDefaultKeyIDQuery, in.DefaultKeyID)

		err := row.Scan(&defaultKeyID)
		if err != nil {
			return typesdb.ServiceConfig{}, err
		}
	}

	// Upsert the service configuration.
	const insertServiceConfigQuery = `INSERT INTO blocky_authz_service_config (created_at, issuer, default_key_id, key_rotation_period)
    VALUES ($1, $2, $3, $4)`

	now := s.time.Now()
	_, err := tx.ExecContext(ctx, insertServiceConfigQuery,
		now,                  // created_at
		in.Issuer,            // issuer
		in.DefaultKeyID,      // default_key_id
		in.KeyRotationPeriod, // key_rotation_period
	)
	if err != nil {
		return typesdb.ServiceConfig{}, err
	}

	return typesdb.ServiceConfig{
		LastUpdatedAt:     now,
		Issuer:            in.Issuer,
		DefaultKeyID:      in.DefaultKeyID,
		KeyRotationPeriod: in.KeyRotationPeriod,
	}, nil
}

// GetServiceConfig is a method to get the service configuration.
func (s *ConfigStorage) GetServiceConfig(ctx context.Context, tx *sql.Tx) (typesdb.ServiceConfig, error) {
	const selectServiceConfigQuery = `SELECT 
    sc.created_at AS created_at, 
    sc.issuer AS issuer, 
    k.sid AS default_key_id, 
    sc.key_rotation_period AS key_rotation_period 
FROM blocky_authz_service_config AS sc
LEFT JOIN blocky_authz_key AS k
    ON sc.default_key_id = k.id
ORDER BY sc.created_at DESC
LIMIT 1`

	row := tx.QueryRowContext(ctx, selectServiceConfigQuery)
	var (
		createdAt         time.Time
		issuer            string
		defaultKeyID      sql.NullString
		keyRotationPeriod time.Duration
	)

	err := row.Scan(&createdAt, &issuer, &defaultKeyID, &keyRotationPeriod)
	if err != nil {
		return typesdb.ServiceConfig{}, err
	}

	return typesdb.ServiceConfig{
		LastUpdatedAt:     createdAt,
		Issuer:            issuer,
		DefaultKeyID:      defaultKeyID.String,
		KeyRotationPeriod: keyRotationPeriod,
	}, nil
}
