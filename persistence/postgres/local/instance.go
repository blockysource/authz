// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package postgreslocal

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"log/slog"
	"strings"

	localdriver "github.com/blockysource/authz/persistence/driver/local"
	"github.com/blockysource/authz/persistence/internal/purge"
)

func init() {
	instancesInsertSQL = purge.SanitizeSQL(instancesInsertSQL)
	instancesGetByProjectSQL = purge.SanitizeSQL(instancesGetByProjectSQL)
	instancesGetSQL = purge.SanitizeSQL(instancesGetSQL)
	instancesListSQL = purge.SanitizeSQL(instancesListSQL)
	instanceConfigInsertSQL = purge.SanitizeSQL(instanceConfigInsertSQL)
	instanceConfigGetSQL = purge.SanitizeSQL(instanceConfigGetSQL)
	instanceAccessTokenConfigGetSQL = purge.SanitizeSQL(instanceAccessTokenConfigGetSQL)
	instanceAccessTokenConfigInsertSQL = purge.SanitizeSQL(instanceAccessTokenConfigInsertSQL)
	instanceRefreshTokenConfigGetSQL = purge.SanitizeSQL(instanceRefreshTokenConfigGetSQL)
	instanceRefreshTokenConfigInsertSQL = purge.SanitizeSQL(instanceRefreshTokenConfigInsertSQL)
}

var _ localdriver.InstancesStorage = (*InstanceStorage)(nil)

// InstanceStorage is a postgres instance storage used for local 'authz' service purpose.
type InstanceStorage struct {
	log *slog.Logger
}

//go:embed queries/instances/instance_insert.sql
var instancesInsertSQL string

// CreateInstance creates a new instance.
func (i *InstanceStorage) CreateInstance(ctx context.Context, tx *sql.Tx, instance localdriver.Instance) error {
	_, err := tx.ExecContext(ctx, instancesInsertSQL,
		instance.ID,
		instance.CreatedAt,
		instance.UpdatedAt,
		instance.DisplayName,
		instance.ProjectID,
	)
	return err
}

//go:embed queries/instances/instance_get_by_project.sql
var instancesGetByProjectSQL string

// GetInstanceByProject gets an instance by its identifier.
func (i *InstanceStorage) GetInstanceByProject(ctx context.Context, tx *sql.Tx, query localdriver.GetProjectInstanceQuery) (localdriver.Instance, error) {
	var instance localdriver.Instance
	err := tx.QueryRowContext(ctx, instancesGetByProjectSQL, query.ProjectID).Scan(
		&instance.ID,
		&instance.CreatedAt,
		&instance.UpdatedAt,
		&instance.DisplayName,
		&instance.ProjectID,
	)
	return instance, err
}

//go:embed queries/instances/instance_get.sql
var instancesGetSQL string

// GetInstance gets an instance by its identifier.
func (i *InstanceStorage) GetInstance(ctx context.Context, tx *sql.Tx, query localdriver.GetInstanceQuery) (localdriver.Instance, error) {
	var instance localdriver.Instance
	err := tx.QueryRowContext(ctx, instancesGetSQL, query.InstanceID).Scan(
		&instance.ID,
		&instance.CreatedAt,
		&instance.UpdatedAt,
		&instance.DisplayName,
		&instance.ProjectID,
	)
	return instance, err
}

//go:embed queries/instances/instance_list.sql
var instancesListSQL string

// ListInstances lists instances that matches the query.
func (i *InstanceStorage) ListInstances(ctx context.Context, tx *sql.Tx, query localdriver.ListInstancesQuery) ([]localdriver.Instance, error) {
	var sb strings.Builder
	sb.WriteString(instancesListSQL)

	if query.Filter != nil {
		return nil, errors.New("filtering is not supported yet")
	}

	if query.Order != nil {
		return nil, errors.New("ordering is not supported yet")
	}

	var out []localdriver.Instance
	rows, err := tx.QueryContext(ctx, sb.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var instance localdriver.Instance
		err = rows.Scan(
			&instance.ID,
			&instance.CreatedAt,
			&instance.UpdatedAt,
			&instance.DisplayName,
			&instance.ProjectID,
		)
		if err != nil {
			return nil, err
		}
		out = append(out, instance)
	}

	return out, nil
}

//go:embed queries/instances/config_insert.sql
var instanceConfigInsertSQL string

// InsertInstanceConfig inserts a new instance config.
func (i *InstanceStorage) InsertInstanceConfig(ctx context.Context, tx *sql.Tx, config localdriver.InstanceConfig) error {
	_, err := tx.ExecContext(ctx, instanceConfigInsertSQL,
		config.InstanceID,
		config.Issuer,
		config.KeyRotationInterval,
	)
	return err
}

//go:embed queries/instances/config_get.sql
var instanceConfigGetSQL string

// GetInstanceConfig gets an instance config by its identifier.
func (i *InstanceStorage) GetInstanceConfig(ctx context.Context, tx *sql.Tx, query localdriver.GetInstanceQuery) (localdriver.InstanceConfig, error) {
	var config localdriver.InstanceConfig
	err := tx.QueryRowContext(ctx, instanceConfigGetSQL, query.InstanceID).Scan(
		&config.InstanceID,
		&config.Issuer,
		&config.KeyRotationInterval,
	)
	return config, err
}

//go:embed queries/instances/access_token_config_insert.sql
var instanceAccessTokenConfigInsertSQL string

// InsertAccessTokenConfig inserts a new instance access token config.
func (i *InstanceStorage) InsertAccessTokenConfig(ctx context.Context, tx *sql.Tx, config localdriver.InstanceAccessTokenConfig) error {
	_, err := tx.ExecContext(ctx, instanceAccessTokenConfigInsertSQL,
		config.InstanceID,
		config.FavoredAlgorithm,
		config.TokenLifetime,
	)
	return err
}

//go:embed queries/instances/access_token_config_get.sql
var instanceAccessTokenConfigGetSQL string

// GetAccessTokenConfig gets an instance access token config by its identifier.
func (i *InstanceStorage) GetAccessTokenConfig(ctx context.Context, tx *sql.Tx, query localdriver.GetInstanceQuery) (localdriver.InstanceAccessTokenConfig, error) {
	var config localdriver.InstanceAccessTokenConfig
	err := tx.QueryRowContext(ctx, instanceAccessTokenConfigGetSQL, query.InstanceID).Scan(
		&config.InstanceID,
		&config.FavoredAlgorithm,
		&config.TokenLifetime,
	)
	return config, err
}

//go:embed queries/instances/refresh_token_config_insert.sql
var instanceRefreshTokenConfigInsertSQL string

// InsertRefreshTokenConfig inserts a new instance refresh token config.
func (i *InstanceStorage) InsertRefreshTokenConfig(ctx context.Context, tx *sql.Tx, config localdriver.InstanceRefreshTokenConfig) error {
	_, err := tx.ExecContext(ctx, instanceRefreshTokenConfigInsertSQL,
		config.InstanceID,
		config.TokenLifetime,
		config.FavoredAlgorithm,
		config.TokenSize,
	)
	return err
}

//go:embed queries/instances/refresh_token_config_get.sql
var instanceRefreshTokenConfigGetSQL string

// GetRefreshTokenConfig gets an instance refresh token config by its identifier.
func (i *InstanceStorage) GetRefreshTokenConfig(ctx context.Context, tx *sql.Tx, query localdriver.GetInstanceQuery) (localdriver.InstanceRefreshTokenConfig, error) {
	var config localdriver.InstanceRefreshTokenConfig
	err := tx.QueryRowContext(ctx, instanceRefreshTokenConfigGetSQL, query.InstanceID).Scan(
		&config.InstanceID,
		&config.TokenLifetime,
		&config.FavoredAlgorithm,
		&config.TokenSize,
	)
	return config, err

}
