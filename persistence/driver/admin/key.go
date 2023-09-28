// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindriver

import (
	"context"
	"database/sql"
	"time"

	uuid "github.com/blockysource/authz/persistence/driver/uuid"

	"github.com/blockysource/authz/persistence/driver/algorithm"
	"github.com/blockysource/blocky-aip/expr"
)

// KeysStorage is a storage for keys.
type KeysStorage interface {
	// CreateKey creates a new key.
	CreateKey(ctx context.Context, tx *sql.Tx, key Key) error

	// InsertKeyIdentifier inserts a new key identifier.
	InsertKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier KeyIdentifier) error

	// LookupKeyIdentifier looks up a key identifier.
	LookupKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier, projectID string) (KeyIdentifier, error)

	// GetKey gets a key by its identifier.
	GetKey(ctx context.Context, tx *sql.Tx, query GetKeyQuery) (Key, error)

	// GetAndLockKey gets a key by its identifier and locks it.
	GetAndLockKey(ctx context.Context, tx *sql.Tx, query GetKeyQuery) (Key, error)

	// ListKeys lists keys.
	ListKeys(ctx context.Context, tx *sql.Tx, query ListKeysQuery) ([]Key, error)

	// HasMoreKeys checks if there are more keys.
	HasMoreKeys(ctx context.Context, tx *sql.Tx, query HasMoreKeysQuery) (bool, error)

	// DeleteKeyIdentifier deletes a key identifier.
	DeleteKeyIdentifier(ctx context.Context, tx *sql.Tx, identifier KeyIdentifier) error

	// CountKeys counts the number of keys.
	CountKeys(ctx context.Context, tx *sql.Tx, query CountKeysQuery) (int64, error)

	// UpdateKey updates a key.
	UpdateKey(ctx context.Context, tx *sql.Tx, query UpdateKeyQuery) error

	// CreateKeyRevision creates a new key revision.
	CreateKeyRevision(ctx context.Context, tx *sql.Tx, revision KeyRevision) error

	// InsertKeyRevisionIdentifier inserts a new key revision identifier.
	InsertKeyRevisionIdentifier(ctx context.Context, tx *sql.Tx, identifier KeyRevisionIdentifier) error

	// GetKeyRevision gets a key revision by its identifier.
	GetKeyRevision(ctx context.Context, tx *sql.Tx, query GetKeyRevisionQuery) (KeyRevision, error)

	// ListKeyRevisions lists key revisions.
	ListKeyRevisions(ctx context.Context, tx *sql.Tx, query ListKeyRevisionsQuery) ([]KeyRevision, error)

	// RevokeKeyRevision revokes a key revision.
	RevokeKeyRevision(ctx context.Context, tx *sql.Tx, query RevokeKeyRevisionQuery) error

	// UpdateLatestKeyRevisionIdentifier upserts a new key revision identifier.
	UpdateLatestKeyRevisionIdentifier(ctx context.Context, tx *sql.Tx, identifier UpdateLatestKeyRevisionIdentifier) error

	// CountKeyRevisions counts the number of key revisions.
	CountKeyRevisions(ctx context.Context, tx *sql.Tx, query CountKeyRevisionsQuery) (int64, error)
}

// ListKeysQuery is a query for listing keys.
type ListKeysQuery struct {
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

// HasMoreKeysQuery is a query for checking if there are more keys.
type HasMoreKeysQuery struct {
	// ProjectID is the project identifier of the keys.
	ProjectID string

	// OrderBy is the order by expression of the keys.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the keys.
	Filter *expr.FilterExpr

	// LastCreatedAt is the last created at time of the keys.
	LastCreatedAt time.Time
}

// CountKeysQuery is a query for counting keys.
type CountKeysQuery struct {
	// ProjectID is the project identifier of the keys.
	ProjectID string

	// Filter is the filter expression of the keys.
	Filter *expr.FilterExpr
}

// UpdateKeyQuery is a query for updating a key.
type UpdateKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyIdentifier is the unique identifier of the key.
	KeyIdentifier string

	// Expr is the update expression of the key.
	Expr *expr.UpdateExpr
}

// GetKeyQuery is a query for getting a key.
type GetKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyIdentifier is the identifier of the key.
	// An identifier can be a key ID, a key alias.
	KeyIdentifier string
}

// ListKeyRevisionsQuery is a query for listing key revisions.
type ListKeyRevisionsQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyIdentifier is the unique identifier of the key.
	KeyIdentifier string

	// PageSize is the page size of the key revisions.
	PageSize int

	// Skip is the number of key revisions to skip.
	Skip int

	// OrderBy is the order by expression of the key revisions.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}

// GetKeyRevisionQuery is a query for getting a key revision.
type GetKeyRevisionQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyIdentifier is the unique identifier of the key.
	KeyIdentifier string

	// KeyRevisionIdentifier is the identifier of the key revision.
	// An identifier can be a key revision ID, a key revision alias.
	KeyRevisionIdentifier string
}

// RevokeKeyRevisionQuery is a query for revoking a key revision.
type RevokeKeyRevisionQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyIdentifier is the unique identifier of the key.
	KeyIdentifier string

	// RevisionIdentifier is the identifier of the key revision.
	// An identifier can be a key revision ID, a key revision alias.
	RevisionIdentifier string

	// RevokedAt is the time when the key revision was revoked.
	RevokedAt time.Time
}

// Key represents a signing key used by the authorization service.
type Key struct {
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
	Algorithm algorithm.SigningAlgorithm

	// RotationPeriod is the rotation period of the key.
	RotationPeriod time.Duration

	// Priority is the priority of the key.
	Priority int

	// Revisions is the number of revisions of the key.
	Revisions int

	// LastRotatedAt is the time when the key was last rotated.
	LastRotatedAt sql.NullTime
}

// KeyIdentifier represents the identifier of a key.
type KeyIdentifier struct {
	// KeyID is the unique identifier of the key.
	KeyID uuid.UUID

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

// KeyRevision represents a single revision of a key.
// It is used directly for signing and verifying signatures.
type KeyRevision struct {
	// ID is the unique identifier of the key revision.
	ID string

	// KeyID is the unique identifier of the key.
	KeyID uuid.UUID

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

// KeyRevisionIdentifier represents the identifier of a key revision.
type KeyRevisionIdentifier struct {
	// KeyRevisionID is the unique identifier of the key revision.
	KeyRevisionID string

	// KeyID is the unique identifier of the key.
	KeyID uuid.UUID

	// Identifier is the identifier of the key revision.
	// An identifier can be a key revision ID, a key revision alias.
	Identifier string
}

// UpdateLatestKeyRevisionIdentifier represents the identifier of a key revision.
type UpdateLatestKeyRevisionIdentifier struct {
	// KeyRevisionID is the unique identifier of the key revision.
	KeyRevisionID string

	// KeyID is the unique identifier of the key.
	KeyID uuid.UUID
}

// CountKeyRevisionsQuery is a query for counting key revisions.
type CountKeyRevisionsQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyIdentifier is the unique identifier of the key.
	KeyIdentifier string

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}
