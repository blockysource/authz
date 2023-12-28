// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package localdriver

import (
	"context"
	"database/sql"
	"time"

	"github.com/blockysource/authz/persistence/driver/algorithmdb"
	uuid "github.com/blockysource/authz/persistence/driver/uuid"
	"github.com/blockysource/blocky-aip/expr"
)

// InstancesStorage is a local instances storage.
// It is used for the internal purpose of the 'authz' service.
type InstancesStorage interface {
	// CreateInstance creates a new instance.
	CreateInstance(ctx context.Context, tx *sql.Tx, instance Instance) error

	// GetInstanceByProject gets an instance by its identifier.
	GetInstanceByProject(ctx context.Context, tx *sql.Tx, query GetProjectInstanceQuery) (Instance, error)

	// GetInstance gets an instance by its identifier.
	GetInstance(ctx context.Context, tx *sql.Tx, query GetInstanceQuery) (Instance, error)

	// ListInstances lists instances that matches the query.
	ListInstances(ctx context.Context, tx *sql.Tx, query ListInstancesQuery) ([]Instance, error)

	// InsertInstanceConfig inserts a new instance config.
	InsertInstanceConfig(ctx context.Context, tx *sql.Tx, config InstanceConfig) error

	// GetInstanceConfig gets an instance config by its identifier.
	GetInstanceConfig(ctx context.Context, tx *sql.Tx, query GetInstanceQuery) (InstanceConfig, error)

	// InsertAccessTokenConfig inserts a new instance access token config.
	InsertAccessTokenConfig(ctx context.Context, tx *sql.Tx, config InstanceAccessTokenConfig) error

	// GetAccessTokenConfig gets an instance access token config by its identifier.
	GetAccessTokenConfig(ctx context.Context, tx *sql.Tx, query GetInstanceQuery) (InstanceAccessTokenConfig, error)

	// InsertRefreshTokenConfig inserts a new instance refresh token config.
	InsertRefreshTokenConfig(ctx context.Context, tx *sql.Tx, config InstanceRefreshTokenConfig) error

	// GetRefreshTokenConfig gets an instance refresh token config by its identifier.
	GetRefreshTokenConfig(ctx context.Context, tx *sql.Tx, query GetInstanceQuery) (InstanceRefreshTokenConfig, error)
}

// Instance represents an authorization service instance.
type Instance struct {
	// ID is the identifier of the instance.
	ID uuid.UUID `behavior:"IDENTIFIER,GEN_ON_CREATE"`

	// ProjectID is the project identifier of the instance.
	ProjectID string `behavior:"IDENTIFIER"`

	// CreatedAt is the time when the instance was created.
	CreatedAt time.Time `behavior:"GEN_ON_CREATE"`

	// UpdatedAt is the time when the instance was last updated.
	UpdatedAt time.Time `behavior:"GEN_ON_CHANGE"`

	// DisplayName is the display name of the instance.
	DisplayName string `behavior:"NON_EMPTY_DEFAULT"`
}

// InstanceConfig represents a config of an instance.
type InstanceConfig struct {
	// InstanceID is the identifier of the instance.
	InstanceID uuid.UUID `behavior:"IDENTIFIER"`

	// Issuer is the name this instance uses to identify as when issuing tokens.
	Issuer string `behavior:"REQUIRED"`

	// KeyRotationInterval is the default period of time between key rotations.
	KeyRotationInterval time.Duration `behavior:"OPTIONAL"`
}

// GetProjectInstanceQuery is a query for getting an instance.
type GetProjectInstanceQuery struct {
	// ProjectID is the project identifier of the instance.
	ProjectID string `behavior:"IDENTIFIER"`
}

// GetInstanceQuery is a query for getting an instance.
type GetInstanceQuery struct {
	// InstanceID is the identifier of the instance.
	InstanceID uuid.UUID `behavior:"IDENTIFIER"`
}

// ListInstancesQuery is a query for listing instances.
type ListInstancesQuery struct {
	// Filter is the filter of the query.
	Filter expr.FilterExpr `behavior:"OPTIONAL"`

	// PageSize is the page size of the query.
	PageSize int `behavior:"OPTIONAL"`

	// Skip is the amount of instances to skip in the query.
	Skip int `behavior:"OPTIONAL"`

	// Order is the sorting of the query.
	Order *expr.OrderByExpr `behavior:"OPTIONAL"`
}

// InstanceAccessTokenConfig represents an access token config of an instance.
type InstanceAccessTokenConfig struct {
	// InstanceID is the identifier of the instance.
	InstanceID uuid.UUID `behavior:"IDENTIFIER"`

	// FavoredAlgorithm is the signing algorithm of the access token.
	FavoredAlgorithm algorithmdb.SigningAlgorithm `behavior:"NON_EMPTY_DEFAULT"`

	// TokenLifetime is the lifetime of the access token.
	TokenLifetime time.Duration `behavior:"NON_EMPTY_DEFAULT"`
}

// InstanceRefreshTokenConfig represents a refresh token config of an instance.
type InstanceRefreshTokenConfig struct {
	// InstanceID is the identifier of the instance.
	InstanceID uuid.UUID `behavior:"IDENTIFIER"`

	// FavoredAlgorithm is the signing algorithm of the refresh token.
	FavoredAlgorithm algorithmdb.SigningAlgorithm `behavior:"NON_EMPTY_DEFAULT"`

	// TokenLifetime is the lifetime of the refresh token.
	TokenLifetime time.Duration `behavior:"NON_EMPTY_DEFAULT"`

	// TokenSize is the size of the refresh token.
	TokenSize int `behavior:"NON_EMPTY_DEFAULT"`
}
