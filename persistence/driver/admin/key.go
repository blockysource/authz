// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindriver

import (
	"context"
	"database/sql"
	"time"

	uuid "github.com/blockysource/authz/persistence/driver/uuid"

	"github.com/blockysource/authz/persistence/driver/algorithmdb"
	"github.com/blockysource/blocky-aip/expr"
)

// KeysStorage is a storage for keys.
type KeysStorage interface {
	// CreateKeyCore creates a new key core.
	CreateKeyCore(ctx context.Context, tx *sql.Tx, key KeyCore) error

	// InsertKeyCoreIdentifier inserts a new key core identifier.
	InsertKeyCoreIdentifier(ctx context.Context, tx *sql.Tx, identifier KeyCoreIdentifier) error

	// LookupKeyCoreIdentifier looks up a key core identifier.
	LookupKeyCoreIdentifier(ctx context.Context, tx *sql.Tx, identifier, projectID string) (KeyCoreIdentifier, error)

	// GetKeyCore gets a key core by its identifier.
	GetKeyCore(ctx context.Context, tx *sql.Tx, query GetKeyCoreQuery) (KeyCore, error)

	// GetAndLockKeyCore gets a key core by its identifier and locks it.
	GetAndLockKeyCore(ctx context.Context, tx *sql.Tx, query GetKeyCoreQuery) (KeyCore, error)

	// ListKeyCores lists key cores.
	ListKeyCores(ctx context.Context, tx *sql.Tx, query ListKeyCoresQuery) ([]KeyCore, error)

	// ListKeyCoreKeys lists keys that matches given query..
	ListKeyCoreKeys(ctx context.Context, tx *sql.Tx, query ListKeyCoreKeysQuery) ([]Key, error)

	// HasMoreKeyCores checks if there are more key cores.
	HasMoreKeyCores(ctx context.Context, tx *sql.Tx, query HasMoreKeyCoresQuery) (bool, error)

	// DeleteKeyCoreIdentifier deletes a key core identifier.
	DeleteKeyCoreIdentifier(ctx context.Context, tx *sql.Tx, identifier KeyCoreIdentifier) error

	// CountKeyCores counts the number of key cores.
	CountKeyCores(ctx context.Context, tx *sql.Tx, query CountKeyCoresQuery) (int64, error)

	// UpdateKeyCore updates a key core.
	UpdateKeyCore(ctx context.Context, tx *sql.Tx, query UpdateKeyCoreQuery) error

	// CreateKey creates a new key.
	CreateKey(ctx context.Context, tx *sql.Tx, key KeyWithSecret) error

	// InsertCoreKeyIdentifier inserts a new key core - key identifier.
	InsertCoreKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier CoreKeyIdentifier) error

	// GetKey gets a key by its identifier.
	GetKey(ctx context.Context, tx *sql.Tx, query GetKeyQuery) (Key, error)

	// GetKeyWithSecret gets a key along with its secret by its identifier.
	GetKeyWithSecret(ctx context.Context, tx *sql.Tx, query GetKeyQuery) (KeyWithSecret, error)

	// GetKeyCoreKey gets a key core by its identifier.
	GetKeyCoreKey(ctx context.Context, tx *sql.Tx, query GetKeyCoreKeyQuery) (Key, error)

	// ListKeys lists keys that matches given query..
	ListKeys(ctx context.Context, tx *sql.Tx, query ListKeysQuery) ([]Key, error)

	// ListKeysWithSecret lists keys along with its secret that matches query.
	ListKeysWithSecret(ctx context.Context, tx *sql.Tx, query ListKeysQuery) ([]KeyWithSecret, error)

	// RevokeKey revokes a key revision.
	RevokeKey(ctx context.Context, tx *sql.Tx, query RevokeKeyQuery) error

	// UpdateLatestCoreKeyIdentifier upserts a new key identifier.
	UpdateLatestCoreKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier UpdateLatestCoreKeyIdentifier) error

	// CountKeys counts the number of keys.
	CountKeys(ctx context.Context, tx *sql.Tx, query CountKeysQuery) (int64, error)

	// CountCoreKeys counts the number of keys.
	CountCoreKeys(ctx context.Context, tx *sql.Tx, query CountKeyCoreKeysQuery) (int64, error)
}

// ListKeyCoresQuery is a query for listing keys.
type ListKeyCoresQuery struct {
	// ProjectID is the project identifier of the keys.
	ProjectID string

	// PageSize is the page size of the keys.
	PageSize int

	// Skip is the number of keys to skip.
	Skip int

	// OrderBy is the order by expression of the keys.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the keys.
	Filter *expr.FilterExpr
}

// HasMoreKeyCoresQuery is a query for checking if there are more keys.
type HasMoreKeyCoresQuery struct {
	// ProjectID is the project identifier of the keys.
	ProjectID string

	// OrderBy is the order by expression of the keys.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the keys.
	Filter *expr.FilterExpr

	// LastCreatedAt is the last created at time of the keys.
	LastCreatedAt time.Time
}

// CountKeyCoresQuery is a query for counting keys.
type CountKeyCoresQuery struct {
	// ProjectID is the project identifier of the keys.
	ProjectID string

	// Filter is the filter expression of the keys.
	Filter *expr.FilterExpr
}

// UpdateKeyCoreQuery is a query for updating a key.
type UpdateKeyCoreQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyCoreIdentifier is the unique identifier of the key.
	KeyCoreIdentifier string

	// Expr is the update expression of the key.
	Expr *expr.UpdateExpr
}

// GetKeyCoreQuery is a query for getting a key.
type GetKeyCoreQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyCoreIdentifier is the identifier of the key.
	// An identifier can be a key ID, a key alias.
	KeyCoreIdentifier string
}

// ListKeysQuery is a query for listing key revisions.
type ListKeysQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// PageSize is the page size of the key revisions.
	PageSize int

	// Skip is the number of key revisions to skip.
	Skip int

	// OrderBy is the order by expression of the key revisions.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}

// ListKeyCoreKeysQuery is a query for listing key revisions.
type ListKeyCoreKeysQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// CoreIdentifier is the unique identifier of the key.
	CoreIdentifier string

	// PageSize is the page size of the key revisions.
	PageSize int

	// Skip is the number of key revisions to skip.
	Skip int

	// OrderBy is the order by expression of the key revisions.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}

// GetKeyQuery is a query for getting a key revision.
type GetKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyID is the unique identifier of the key.
	KeyID string
}

// GetKeyCoreKeyQuery is a query for getting a key revision.
type GetKeyCoreKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// CoreIdentifier is the unique identifier of the key.
	CoreIdentifier string

	// KeyIdentifier is the unique identifier of the key.
	KeyIdentifier string
}

// RevokeKeyQuery is a query for revoking a key revision.
type RevokeKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyID is the unique identifier of the key.
	KeyID string

	// RevokedAt is the time when the key revision was revoked.
	RevokedAt time.Time
}

// KeyCore represents a signing key used by the authorization service.
type KeyCore struct {
	// ID is the unique identifier of the key.
	ID uuid.UUID

	// ProjectID is the project identifier of the key.
	ProjectID string

	// CreatedAt is the time when the key was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the key was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the key.
	DisplayName string

	// Algorithm is the signing algorithm of the key.
	Algorithm algorithmdb.SigningAlgorithm

	// RotationInterval is the rotation period of the key.
	RotationInterval time.Duration

	// Priority is the priority of the key.
	Priority int

	// DerivedKeysCount is the number of revisions of the key.
	DerivedKeysCount int

	// LastRotatedAt is the time when the key was last rotated.
	LastRotatedAt sql.NullTime
}

// KeyCoreIdentifier represents the identifier of a key.
type KeyCoreIdentifier struct {
	// KeyCoreID is the unique identifier of the key.
	KeyCoreID uuid.UUID

	// ProjectID is the project identifier of the key.
	ProjectID string

	// Identifier is the identifier of the key.
	// An identifier can be a key ID, a key alias.
	Identifier string
}

// KeyAlias represents an alias of a key.
type KeyAlias struct {
	// KeyID is the unique identifier of the key.
	KeyID uuid.UUID

	// ProjectID is the project identifier of the key alias.
	ProjectID string

	// Alias is the alias of the key.
	Alias string
}

// KeyWithSecret represents a single key along with its encrypted secret.
// It is used directly for signing and verifying signatures.
type KeyWithSecret struct {
	// ID is the unique identifier of the key revision.
	ID string

	// CoreID is the unique identifier of the key.
	CoreID uuid.UUID

	// ProjectID is the project identifier of the key.
	ProjectID string

	// CreatedAt is the time when the key revision was created.
	CreatedAt time.Time

	// RevokedAt is the time when the key revision was revoked.
	// If this field takes time.Time{} value, the key revision is not revoked.
	RevokedAt sql.NullTime

	// Priority is the priority of the key revision, derived from the key.
	Priority int

	// Revision is the incremental revision of the key revision.
	Revision int

	// EncryptedSecret is the encrypted secret of the key revision.
	EncryptedSecret []byte
}

// Key represents a single key.
type Key struct {
	// ID is the unique identifier of the key revision.
	ID string

	// CoreID is the unique identifier of the key.
	CoreID uuid.UUID

	// ProjectID is the project identifier of the key.
	ProjectID string

	// CreatedAt is the time when the key revision was created.
	CreatedAt time.Time

	// RevokedAt is the time when the key revision was revoked.
	// If this field takes time.Time{} value, the key revision is not revoked.
	RevokedAt sql.NullTime

	// Priority is the priority of the key revision, derived from the key.
	Priority int

	// Revision is the incremental revision of the key revision.
	Revision int
}

// CoreKeyIdentifier represents the identifier of a key revision.
type CoreKeyIdentifier struct {
	// KeyID is the unique identifier of the key revision.
	KeyID string

	// CoreID is the unique identifier of the key.
	CoreID uuid.UUID

	// Identifier is the identifier of the key revision.
	// An identifier can be a key revision ID, a key revision alias.
	Identifier string
}

// UpdateLatestCoreKeyIdentifier represents the identifier of a key revision.
type UpdateLatestCoreKeyIdentifier struct {
	// KeyID is the unique identifier of the key revision.
	KeyID string

	// CoreID is the unique identifier of the key.
	CoreID uuid.UUID
}

// CountKeysQuery is a query for counting key revisions.
type CountKeysQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}

// CountKeyCoreKeysQuery is a query for counting key revisions.
type CountKeyCoreKeysQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// CoreIdentifier is the unique identifier of the key.
	CoreIdentifier string

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}
