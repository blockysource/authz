// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindriver

import (
	"context"
	"database/sql"
	"time"

	uuid "github.com/blockysource/authz/persistence/driver/uuid"

	"github.com/blockysource/blocky-aip/expr"
)

// ResourceStorage is a database storage for the resource and its configuration.
type ResourceStorage interface {
	// CreateResourceManager creates a new resource manager.
	CreateResourceManager(ctx context.Context, tx *sql.Tx, manager ResourceManager) error

	// InsertResourceManagerAlias upserts a resource manager alias.
	InsertResourceManagerAlias(ctx context.Context, tx *sql.Tx, alias ResourceManagerAlias) error

	// InsertResourceManagerIdentifier upserts a resource manager identifier.
	InsertResourceManagerIdentifier(ctx context.Context, tx *sql.Tx, identifier ResourceManagerIdentifier) error

	// GetResourceManager gets a resource manager by its identifier.
	GetResourceManager(ctx context.Context, tx *sql.Tx, query GetResourceManagerQuery) (ResourceManager, error)

	// ListResourceManagers lists resource managers.
	ListResourceManagers(ctx context.Context, tx *sql.Tx, query ListResourceManagersQuery) (ListResourceManagersResult, error)

	// DeleteResourceManager deletes a resource manager.
	DeleteResourceManager(ctx context.Context, tx *sql.Tx, query GetResourceManagerQuery) error

	// DeleteResourceManagerAlias deletes a resource manager alias.
	DeleteResourceManagerAlias(ctx context.Context, tx *sql.Tx, alias ResourceManagerAlias) error

	// DeleteResourceManagerIdentifier deletes a resource manager identifier.
	DeleteResourceManagerIdentifier(ctx context.Context, tx *sql.Tx, identifier ResourceManagerIdentifier) error


}

// GetResourceManagerQuery is a query for getting a resource manager.
type GetResourceManagerQuery struct {
	// ProjectID is the project identifier of the resource manager.
	ProjectID string

	// Identifier is the identifier of the resource manager.
	Identifier string
}

// ListResourceManagersQuery is a query for listing resource managers.
type ListResourceManagersQuery struct {
	// ProjectID is the project identifier of the resource managers.
	ProjectID string

	// PageSize is the page size of the resource managers.
	PageSize int

	// Skip is the skip of the resource managers.
	Skip int

	// OrderBy is the order by expression of the resource managers.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the resource managers.
	Filter *expr.FilterExpr
}

// ListResourceManagersResult is a result of listing resource managers.
type ListResourceManagersResult struct {
	// ResourceManagers is the resource managers.
	ResourceManagers []ResourceManager

	// TotalCount is the total count of the resource managers.
	TotalCount int
}

// ResourceManager is a resource manager.
type ResourceManager struct {
	// ID is the unique identifier of the resource manager.
	ID uuid.UUID

	// ProjectID is the project identifier of the resource manager.
	ProjectID string

	// CreatedAt is the time when the resource manager was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the resource manager was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the resource manager.
	DisplayName string
}

// ResourceManagerAlias is an alias of a resource manager.
type ResourceManagerAlias struct {
	// ResourceManagerID is the unique identifier of the resource manager.
	ResourceManagerID uuid.UUID

	// ProjectID is the project identifier of the resource manager alias.
	ProjectID string

	// Alias is the alias of the resource manager.
	Alias string
}

// ResourceManagerIdentifier represents the identifier of a resource manager.
type ResourceManagerIdentifier struct {
	// ResourceManagerID is the unique identifier of the resource manager.
	ResourceManagerID uuid.UUID

	// ProjectID is the project identifier of the resource manager.
	ProjectID string

	// Identifier is the identifier of the resource manager.
	// An identifier can be a resource manager ID, a resource manager alias.
	Identifier string
}

// ResourcePermission represents a permission of a resource.
type ResourcePermission struct {
	// ID is the unique identifier of the resource permission.
	ID uuid.UUID

	// ResourceManagerID is the unique identifier of the resource manager.
	ResourceManagerID uuid.UUID

	// ProjectID is the project identifier of the resource permission.
	ProjectID string

	// CreatedAt is the time when the resource permission was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the resource permission was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the resource permission.
	DisplayName string

	// Description is the description of the resource permission.
	Description string

	// Scope is the scope of the resource permission.
	// A scope is the authorization scope of the resource permission.
	// It is used within the authorization system to determine if a resource permission is authorized.
	// This needs to be unique per project.
	Scope string
}

// ResourcePermissionAlias is an alias of a resource permission.
type ResourcePermissionAlias struct {
	// ResourcePermissionID is the unique identifier of the resource permission.
	ResourcePermissionID uuid.UUID

	// ProjectID is the project identifier of the resource permission alias.
	ProjectID string

	// Alias is the alias of the resource permission.
	Alias string
}

// ResourcePermissionIdentifier represents the identifier of a resource permission.
type ResourcePermissionIdentifier struct {
	// ResourcePermissionID is the unique identifier of the resource permission.
	ResourcePermissionID uuid.UUID

	// ProjectID is the project identifier of the resource permission.
	ProjectID string

	// Identifier is the identifier of the resource permission.
	// An identifier can be a resource permission ID, a resource permission alias.
	Identifier string
}
