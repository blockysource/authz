// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package localdb

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/google/uuid"

	localdriver "github.com/blockysource/authz/persistence/driver/local"
	"github.com/blockysource/authz/types/algorithm"
	"github.com/blockysource/blockysql"
)

// InstancesStorage is a local instance storage used for local 'authz' service purpose.
type InstancesStorage struct {
	db *blockysql.DB
	d  localdriver.InstancesStorage

	log *slog.Logger
}

// GetProjectInstanceQuery is a query to get an instance by its project identifier.
type GetProjectInstanceQuery struct {
	// ProjectID is the project identifier of the instance.
	ProjectID string
}

// GetInstanceByProject gets an instance by its project identifier.
func (i *InstancesStorage) GetInstanceByProject(ctx context.Context, query GetProjectInstanceQuery) (*Instance, error) {
	var instance Instance
	err := i.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		inst, err := i.d.GetInstanceByProject(ctx, tx, localdriver.GetProjectInstanceQuery{
			ProjectID: query.ProjectID,
		})
		if err != nil {
			return err
		}

		instance.ID = uuid.UUID(inst.ID)
		instance.ProjectID = inst.ProjectID
		instance.CreatedAt = inst.CreatedAt
		instance.UpdatedAt = inst.UpdatedAt
		instance.DisplayName = inst.DisplayName

		c, err := i.d.GetInstanceConfig(ctx, tx, localdriver.GetInstanceQuery{
			InstanceID: inst.ID,
		})
		if err != nil {
			return err
		}

		instance.Config.Issuer = c.Issuer
		instance.Config.KeyRotationInterval = c.KeyRotationInterval

		atc, err := i.d.GetAccessTokenConfig(ctx, tx, localdriver.GetInstanceQuery{
			InstanceID: inst.ID,
		})
		if err != nil {
			return err
		}

		instance.AccessTokenConfig.FavoredAlgorithm = algorithm.SigningAlgorithm(atc.FavoredAlgorithm)
		instance.AccessTokenConfig.TokenLifetime = atc.TokenLifetime

		rtc, err := i.d.GetRefreshTokenConfig(ctx, tx, localdriver.GetInstanceQuery{
			InstanceID: inst.ID,
		})
		if err != nil {
			return err
		}

		instance.RefreshTokenConfig.FavoredAlgorithm = algorithm.SigningAlgorithm(rtc.FavoredAlgorithm)
		instance.RefreshTokenConfig.TokenLifetime = rtc.TokenLifetime
		instance.RefreshTokenConfig.TokenSize = rtc.TokenSize

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &instance, nil
}

type (
	// Instance represents an authorization service instance for given project.
	Instance struct {
		// ID is the identifier of the instance.
		ID uuid.UUID

		// ProjectID is the project identifier of the instance.
		ProjectID string

		// CreatedAt is the time when the instance was created.
		CreatedAt time.Time

		// UpdatedAt is the time when the instance was last updated.
		UpdatedAt time.Time

		// DisplayName is the display name of the instance.
		DisplayName string

		// Config is the config of the instance.
		Config InstanceConfig

		// AccessTokenConfig is the access token config of the instance.
		AccessTokenConfig InstanceAccessTokenConfig

		// RefreshTokenConfig is the refresh token config of the instance.
		RefreshTokenConfig InstanceRefreshTokenConfig
	}
	// InstanceConfig represents a config of an instance.
	InstanceConfig struct {
		// Issuer is the issuer of the instance.
		Issuer string

		// KeyRotationInterval is the key rotation interval of the instance.
		KeyRotationInterval time.Duration
	}
	// InstanceAccessTokenConfig represents an access token config of an instance.
	InstanceAccessTokenConfig struct {
		// FavoredAlgorithm is the favored algorithm of the access token.
		FavoredAlgorithm algorithm.SigningAlgorithm

		// TokenLifetime is the lifetime of the access token.
		TokenLifetime time.Duration
	}
	// InstanceRefreshTokenConfig represents a refresh token config of an instance.
	InstanceRefreshTokenConfig struct {
		// FavoredAlgorithm is the favored algorithm of the refresh token.
		FavoredAlgorithm algorithm.SigningAlgorithm

		// TokenLifetime is the lifetime of the refresh token.
		TokenLifetime time.Duration

		// TokenSize is the bytes size of the refresh token.
		TokenSize int
	}
)
