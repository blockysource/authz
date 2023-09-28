// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindriver

import (
	"time"

	"github.com/blockysource/authz/persistence/driver/algorithm"
)

// Client represents a client.
type Client struct {
	// ID is the unique identifier of the client.
	ID string

	// ProjectID is the project identifier of the client.
	ProjectID string

	// CreatedAt is the time when the client was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the client was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the client.
	DisplayName string
}

// ClientAlias is an alias of a client.
type ClientAlias struct {
	// ClientID is the unique identifier of the client.
	ClientID string

	// ProjectID is the project identifier of the client alias.
	ProjectID string

	// Alias is the alias of the client.
	Alias string
}

// ClientIdentifier represents the identifier of a client.
type ClientIdentifier struct {
	// ClientID is the unique identifier of the client.
	ClientID string

	// ProjectID is the project identifier of the client.
	ProjectID string

	// Identifier is the identifier of the client.
	// An identifier can be a client ID, a client alias.
	Identifier string
}

// ClientSigningAlgorithm represents a signing algorithm of a client.
type ClientSigningAlgorithm struct {
	// ClientID is the unique identifier of the client.
	ClientID string

	// Algorithm is the signing algorithm of the client.
	Algorithm algorithm.SigningAlgorithm

	// Priority is the priority of the signing algorithm.
	// This is used to determine order of signing algorithms matched
	// for given client.
	Priority int
}

// ClientCredentials represents the credentials of a client.
type ClientCredentials struct {
	// ClientID is the unique identifier of the client.
	ClientID string

	// ProjectID is the project identifier of the client.
	ProjectID string

	// CreatedAt is the time when the client credentials were created.
	CreatedAt time.Time

	// Secret is the secret of the client credentials.
	Secret []byte

	// SecretHash is the hash of the secret of the client credentials.
	SecretHash []byte
}
