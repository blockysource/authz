package typesdb

import (
	"database/sql"
	"time"

	"github.com/blockysource/authz/types/signalg"
)

// CreateKey is the input to the CreateKey method.
type CreateKey struct {
	// TableID is an optional table identifier
	// that was reserved for the key.
	// This cannot be provided by the user.
	TableID int32

	// KeyID is an optional string key identifier.
	// If not provided it will be generated.
	KeyID string

	// CreateTime is the creation time of the key.
	CreateTime time.Time

	// DisplayName is the name of the key.
	// If not provided
	DisplayName string

	// RotationPeriod is the time period after which the key should be rotated.
	RotationPeriod time.Duration

	// SigningAlgorithms defines the signing algorithms that are used by the key.
	SigningAlgorithms []signalg.SigningAlgorithm

	// Priority is the priority of the key.
	Priority int32

	// Active is a flag that indicates if newly created key needs to be activated.
	Active bool
}

// Key is a model of the key that is stored in the database.
type Key struct {
	// TableID is the table identifier of the key.
	// This is the primary key in the database.
	TableID int32

	// KeyID is the string key identifier.
	KeyID string

	// CreatedAt is the time the key was created.
	CreatedAt time.Time

	// DisplayName is the name of the key.
	DisplayName string

	// RotationPeriod is the time period after which the key should be rotated.
	RotationPeriod time.Duration

	// Algorithms defines the signing algorithms that are used by the key.
	Algorithms []signalg.SigningAlgorithm

	// Priority is the priority of the key.
	Priority int32

	// Active is a flag that indicates if the key is active.
	Active bool

	// LastRotatedAt is the time the key was last rotated.
	LastRotatedAt sql.NullTime

	// RevokedAt is the time the key was revoked.
	RevokedAt sql.NullTime

	// Versions number defines the number of key versions.
	Versions int32
}

const (
	// KeyFieldTableID is well-known Key field names.
	KeyFieldTableID = "TableID"
	// KeyFieldKeyID is well-known Key field names.
	KeyFieldKeyID = "KeyID"
	// KeyFieldCreatedAt is well-known Key field names.
	KeyFieldCreatedAt = "CreatedAt"
	// KeyFieldDisplayName is well-known Key field names.
	KeyFieldDisplayName = "DisplayName"
	// KeyFieldRotationPeriod is well-known Key field names.
	KeyFieldRotationPeriod = "RotationPeriod"
	// KeyFieldAlgorithms is well-known Key field names.
	KeyFieldAlgorithms = "Algorithms"
	// KeyFieldPriority is well-known Key field names.
	KeyFieldPriority = "Priority"
	// KeyFieldActive is well-known Key field names.
	KeyFieldActive = "Active"
	// KeyFieldLastRotatedAt is well-known Key field names.
	KeyFieldLastRotatedAt = "LastRotatedAt"
	// KeyFieldRevokedAt is well-known Key field names.
	KeyFieldRevokedAt = "RevokedAt"
	// KeyFieldVersions is well-known Key field names.
	KeyFieldVersions = "Versions"
)

// ListKeysQuery is a request message for listing keys.
type ListKeysQuery struct {
	// PageSize is the size of the page to return.
	PageSize int32

	// Offset is the offset of the page to return.
	Offset int64

	// Filters is a list of filters to apply.
	Filters []FieldFilter

	// Sorting order of the query.
	Order []FieldOrder
}

// ListKeysResult is a result of the ListKeysQuery admin storage.
type ListKeysResult struct {
	// Keys is the list of results.
	Keys []Key

	// TotalSize is the total size of the result set.
	TotalSize int32
}

// DeleteKey is the input to the DeleteKey method.
type DeleteKey struct {
	// KeyID is the string key identifier.
	KeyID string
}
