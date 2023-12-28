// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package postgresadmin

import (
	"context"
	"database/sql"
	_ "embed"
	"log/slog"

	admindriver "github.com/blockysource/authz/persistence/driver/admin"
	"github.com/blockysource/authz/persistence/internal/purge"
)

func init() {
	instancesGetSQL = purge.SanitizeSQL(instancesGetSQL)
	instanceAccessTokenConfigGetSQL = purge.SanitizeSQL(instanceAccessTokenConfigGetSQL)
}

var _ admindriver.InstanceStorage = (*InstanceStorage)(nil)

// InstanceStorage is a postgres instance storage used for admin 'authz' service purpose.
type InstanceStorage struct {
	log *slog.Logger
}

// CreateInstance creates a new instance.
// Implements admindriver.InstanceStorage.
func (i *InstanceStorage) CreateInstance(ctx context.Context, tx *sql.Tx, instance admindriver.Instance) error {
	// TODO implement me
	panic("implement me")
}

//go:embed queries/instances/instance_get.sql
var instancesGetSQL string

// GetInstance gets an instance by its identifier.
func (i *InstanceStorage) GetInstance(ctx context.Context, tx *sql.Tx, query admindriver.GetInstanceQuery) (admindriver.Instance, error) {
	row := tx.QueryRowContext(ctx, instancesGetSQL, query.ProjectID)

	var instance admindriver.Instance
	err := row.Scan(
		&instance.CreatedAt,
		&instance.UpdatedAt,
		&instance.DisplayName,
		&instance.ProjectID,
	)
	if err != nil {
		return admindriver.Instance{}, err
	}

	return instance, nil
}

func (i *InstanceStorage) InsertAccessTokenConfig(ctx context.Context, tx *sql.Tx, config admindriver.InstanceAccessTokenConfig) error {
	// TODO implement me
	panic("implement me")
}

//go:embed queries/instances/access_token_config_get.sql
var instanceAccessTokenConfigGetSQL string

func (i *InstanceStorage) GetAccessTokenConfig(ctx context.Context, tx *sql.Tx, query admindriver.GetInstanceQuery) (admindriver.InstanceAccessTokenConfig, error) {
	row := tx.QueryRowContext(ctx, instanceAccessTokenConfigGetSQL, query.ProjectID)

	var config admindriver.InstanceAccessTokenConfig
	err := row.Scan(
		&config.FavoredSigningAlgorithm,
		&config.TokenLifetime,
		&config.ProjectID,
	)
	if err != nil {
		return admindriver.InstanceAccessTokenConfig{}, err
	}

	return config, nil
}

func (i *InstanceStorage) UpdateAccessTokenConfig(ctx context.Context, tx *sql.Tx, config admindriver.InstanceAccessTokenConfig) error {
	// TODO implement me
	panic("implement me")
}

func (i *InstanceStorage) InsertRefreshTokenConfig(ctx context.Context, tx *sql.Tx, config admindriver.InstanceRefreshTokenConfig) error {
	// TODO implement me
	panic("implement me")
}

func (i *InstanceStorage) GetRefreshTokenConfig(ctx context.Context, tx *sql.Tx, query admindriver.GetInstanceQuery) (admindriver.InstanceRefreshTokenConfig, error) {
	// TODO implement me
	panic("implement me")
}

func (i *InstanceStorage) UpdateRefreshTokenConfig(ctx context.Context, tx *sql.Tx, config admindriver.InstanceRefreshTokenConfig) error {
	// TODO implement me
	panic("implement me")
}
