package admintypesv1

import (
	"database/sql"
	"time"

	"github.com/blockysource/authz/persistence/dbtypes"
)

// CreateKey is the input to the CreateKey method.
type CreateKey struct {
	// KeyID is an optional string key identifier.
	// If not provided it will be generated.
	KeyID string

	// DisplayName is the name of the key.
	// If not provided
	DisplayName string

	// RotationPeriod is the time period after which the key should be rotated.
	RotationPeriod time.Duration

	// SigningAlgorithms defines the signing algorithms that are used by the key.
	SigningAlgorithms []dbtypes.SigningAlgorithm

	// Priority is the priority of the key.
	Priority int32
}

// Key is a model of the key that is stored in the database.
type Key struct {
	// KeyID is the string key identifier.
	KeyID string

	// CreatedAt is the time the key was created.
	CreatedAt time.Time

	// DisplayName is the name of the key.
	DisplayName string

	// RotationPeriod is the time period after which the key should be rotated.
	RotationPeriod time.Duration

	// Algorithms defines the signing algorithms that are used by the key.
	Algorithms []dbtypes.SigningAlgorithm

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

// ListKeysQuery is a request message for listing keys.
type ListKeysQuery struct {
	// PageSize is the size of the page to return.
	PageSize int32

	// Offset is the offset of the page to return.
	Offset   int64
}

// ListKeysResult is a result of the ListKeysQuery admin storage.
type ListKeysResult struct {
	// Keys is the list of results.
	Keys      []Key

	// TotalSize is the total size of the result set.
	TotalSize int32
}
