// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindriver

import (
	"context"
	"database/sql"
	"time"

	"github.com/blockysource/authz/persistence/driver/algorithmdb"
	"github.com/blockysource/authz/persistence/driver/clientdb"
	uuid "github.com/blockysource/authz/persistence/driver/uuid"
)

// ClientsStorage is a storage for clients.
type ClientsStorage interface {
	// InsertClient inserts a client.
	InsertClient(ctx context.Context, tx *sql.Tx, in Client) error

	// GetClient gets a single client by given query.
	GetClient(ctx context.Context, tx *sql.Tx, query GetClient) (Client, error)

	// InsertClientAlias inserts a client alias.
	InsertClientAlias(ctx context.Context, tx *sql.Tx, in ClientAlias) error

	// InsertClientIdentifier inserts a client identifier.
	InsertClientIdentifier(ctx context.Context, tx *sql.Tx, in ClientIdentifier) error

	// InsertClientSigningAlgorithm inserts a client signing algorithm.
	InsertClientSigningAlgorithm(ctx context.Context, tx *sql.Tx, in ClientSigningAlgorithm) error

	// InsertClientCredentials inserts a client credentials.
	InsertClientCredentials(ctx context.Context, tx *sql.Tx, in ClientCredentials) error

	// InsertClientResourcePermission inserts a client permission.
	InsertClientResourcePermission(ctx context.Context, tx *sql.Tx, in ClientResourcePermission) error
}

// GetClient gets a client.
type GetClient struct {
	ProjectID        string
	ClientIdentifier string
}

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

	// Type is the type of the client.
	Type clientdb.ClientType

	// DisplayName is the display name of the client.
	DisplayName string

	// OrganizationInternal denotes if the client is an internal client for the project organization.
	OrganizationInternal bool
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

// ClientSigningAlgorithmsQuery lists client signing algorithms.
type ClientSigningAlgorithmsQuery struct {
	// ProjectID is the project identifier of the client.
	ProjectID string

	// ClientID is the unique identifier of the client.
	ClientID string
}

// ClientSigningAlgorithm represents a signing algorithm of a client.
type ClientSigningAlgorithm struct {
	// ClientID is the unique identifier of the client.
	// This is not returned from the database on ClientSigningAlgorithmsQuery.
	ClientID string

	// Algorithm is the signing algorithm of the client.
	Algorithm algorithmdb.SigningAlgorithm

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

	// UpdatedAt is the time when the client credentials were last updated.
	UpdatedAt time.Time

	// SecretHash is the hash of the secret of the client credentials.
	SecretHash []byte
}

// ClientResourcePermission represents a resource permission of a client.
type ClientResourcePermission struct {
	// ClientID is the unique identifier of the client.
	ClientID string

	// ResourcePermissionID is the unique identifier of the resource permission.
	ResourcePermissionID uuid.UUID

	// ProjectID is the project identifier of the client.
	ProjectID string
}
