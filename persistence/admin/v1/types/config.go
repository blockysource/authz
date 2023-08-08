package admintypesv1

import (
	"time"
)

// UpsertServiceConfig is the input to the UpsertServiceConfig method.
type UpsertServiceConfig struct {
	// Issuer is the issuer of the service.
	Issuer string

	// DefaultKeyID is the default key identifier of the service.
	DefaultKeyID string

	// KeyRotationPeriod is the time period after which the key should be rotated.
	// If not provided, no default key rotation will be performed, and only keys with specified rotation period
	// will be rotated.
	KeyRotationPeriod time.Duration
}

// ServiceConfig is a model of the service config that is stored in the database.
type ServiceConfig struct {
	// LastUpdatedAt is the time the service config was last updated.
	LastUpdatedAt time.Time

	// Issuer is the issuer of the service.
	Issuer string

	// DefaultKeyID is the default key identifier of the service.
	DefaultKeyID string

	// KeyRotationPeriod is the time period after which the key should be rotated.
	KeyRotationPeriod time.Duration
}
