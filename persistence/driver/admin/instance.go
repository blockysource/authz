// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindriver

import (
	"context"
	"database/sql"
	"time"

	uuid "github.com/blockysource/authz/persistence/driver/uuid"

	"github.com/blockysource/authz/persistence/driver/algorithmdb"
)

// InstanceStorage is a database storage for the instance and its configuration.
type InstanceStorage interface {
	// CreateInstance creates a new instance.
	// This should not be done in general manually by the admin user, but rather m2m on event of project creation.
	// But a manual creation should be possible, in case when the instance is not created (error).
	CreateInstance(ctx context.Context, tx *sql.Tx, instance Instance) error

	// GetInstance gets an instance by its identifier.
	GetInstance(ctx context.Context, tx *sql.Tx, query GetInstanceQuery) (Instance, error)

	// GetAccessTokenConfig gets an instance access token config by its identifier.
	GetAccessTokenConfig(ctx context.Context, tx *sql.Tx, query GetInstanceQuery) (InstanceAccessTokenConfig, error)

	// UpdateAccessTokenConfig updates an instance access token config.
	UpdateAccessTokenConfig(ctx context.Context, tx *sql.Tx, config InstanceAccessTokenConfig) error

	// InsertRefreshTokenConfig inserts a new instance refresh token config.
	InsertRefreshTokenConfig(ctx context.Context, tx *sql.Tx, config InstanceRefreshTokenConfig) error

	// GetRefreshTokenConfig gets an instance refresh token config by its identifier.
	GetRefreshTokenConfig(ctx context.Context, tx *sql.Tx, query GetInstanceQuery) (InstanceRefreshTokenConfig, error)

	// UpdateRefreshTokenConfig updates an instance refresh token config.
	UpdateRefreshTokenConfig(ctx context.Context, tx *sql.Tx, config InstanceRefreshTokenConfig) error
}

// GetInstanceQuery is a query for getting an instance.
type GetInstanceQuery struct {
	// ProjectID is the project identifier of the instance.
	ProjectID string
}

// Instance represents an authorization service instance.
type Instance struct {
	// ProjectID is the project identifier of the instance.
	ProjectID string

	// CreatedAt is the time when the instance was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the instance was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the instance.
	DisplayName string
}

// InstanceAccessTokenConfig represents the configuration of an instance access token.
type InstanceAccessTokenConfig struct {
	// ProjectID is the project identifier of the instance.
	ProjectID string

	// FavoredSigningAlgorithm is the favored signing algorithm of the instance.
	FavoredSigningAlgorithm algorithmdb.SigningAlgorithm

	// TokenLifetime is the expiration of the instance access token.
	TokenLifetime time.Duration
}

// InstanceRefreshTokenConfig represents the configuration of an instance refresh token.
type InstanceRefreshTokenConfig struct {
	// InstanceID is the unique identifier of the instance.
	InstanceID uuid.UUID

	// ProjectID is the project identifier of the instance.
	ProjectID string

	// TokenExpiration is the expiration of the instance refresh token.
	TokenExpiration time.Duration

	// FavoredSigningAlgorithm is the favored signing algorithm of the instance.
	FavoredSigningAlgorithm algorithmdb.SigningAlgorithm

	// TokenSize is the size of the instance refresh token.
	TokenSize int
}
