// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindb

import (
	"context"
	"database/sql"
	"errors"
	"github.com/blockysource/authz/deps"
	postgresadmin "github.com/blockysource/authz/persistence/postgres/admin"
	"github.com/blockysource/blockysql/driver"
	"log/slog"
	"time"

	admindriver "github.com/blockysource/authz/persistence/driver/admin"
	"github.com/blockysource/authz/persistence/driver/clientdb"
	"github.com/blockysource/authz/types"
	"github.com/blockysource/blockysql"
)

// ClientsStorage is a storage for clients.
type ClientsStorage struct {
	d   admindriver.ClientsStorage
	db  *blockysql.DB
	log *slog.Logger
}

// NewClientsStorage creates a new instance of the ClientsStorage.
func NewClientsStorage(d *deps.Dependencies) (*ClientsStorage, error) {
	logger := slog.New(d.Logger).With(
		slog.String("service", "authz"),
		slog.String("component", "admin"),
		slog.String("storage", "clients"),
	)

	var drv admindriver.ClientsStorage
	switch d.DB.Dialect() {
	case driver.DialectPostgres:
		drv = postgresadmin.NewClientStorage(logger)
	default:
		return nil, errors.New("blockysql: unsupported dialect")
	}
	cs := &ClientsStorage{
		d:   drv,
		db:  d.DB,
		log: logger,
	}
	return cs, nil
}

// CreateClient creates a client.
type CreateClient struct {
	// ProjectID is the project identifier of the client.
	ProjectID string `field_behavior:"REQUIRED"`

	// ClientID is the unique identifier of the client.
	ClientID string `field_behavior:"REQUIRED"`

	// SecretHash is the secret of the client.
	// If the client type is public then this field is ignored.
	SecretHash []byte `field_behavior:"OPTIONAL"`

	// DisplayName is the display name of the client.
	// This is an optional field.
	DisplayName string `field_behavior:"OPTIONAL"`

	// Alias is the alias of the client.
	Alias string `field_behavior:"OPTIONAL"`

	// Type is the type of the client.
	Type types.ClientType `field_behavior:"REQUIRED"`

	// OrganizationInternal denotes if the client is an internal client for the project organization.
	OrganizationInternal bool `field_behavior:"REQUIRED"`
}

// CreateClient creates a client.
func (c *ClientsStorage) CreateClient(ctx context.Context, in CreateClient) (types.Client, error) {
	var out types.Client
	err := c.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		now := time.Now().Truncate(time.Microsecond)
		client := admindriver.Client{
			ID:                   in.ClientID,
			ProjectID:            in.ProjectID,
			CreatedAt:            now,
			UpdatedAt:            now,
			DisplayName:          in.DisplayName,
			Type:                 clientdb.ClientType(in.Type),
			OrganizationInternal: in.OrganizationInternal,
		}
		// Insert the client.
		err := c.d.InsertClient(ctx, tx, client)
		if err != nil {
			return err
		}

		// Insert the client identifier.
		err = c.d.InsertClientIdentifier(ctx, tx, admindriver.ClientIdentifier{
			ClientID:   client.ID,
			ProjectID:  client.ProjectID,
			Identifier: client.ID,
		})
		if err != nil {
			return err
		}

		if in.Alias != "" {
			// Insert the client alias.
			err = c.d.InsertClientAlias(ctx, tx, admindriver.ClientAlias{
				ClientID:  client.ID,
				ProjectID: client.ProjectID,
				Alias:     in.Alias,
			})
			if err != nil {
				return err
			}

			// Insert the client identifier.
			err = c.d.InsertClientIdentifier(ctx, tx, admindriver.ClientIdentifier{
				ClientID:   client.ID,
				ProjectID:  client.ProjectID,
				Identifier: in.Alias,
			})
			if err != nil {
				return err
			}
		}

		// if len(in.Algorithms) > 0 {
		// 	// Insert the client signing algorithms.
		// 	// TODO: Make this a batch insert.
		// 	for _, alg := range in.Algorithms {
		// 		err = c.d.InsertClientSigningAlgorithm(ctx, tx, admindriver.ClientSigningAlgorithm{
		// 			ClientID:  client.ID,
		// 			Algorithm: algorithmdb.SigningAlgorithm(alg.Algorithm),
		// 			Priority:  alg.Priority,
		// 		})
		// 		if err != nil {
		// 			return err
		// 		}
		// 	}
		// }

		if len(in.SecretHash) != 0 {
			// Insert the client credentials.
			err = c.d.InsertClientCredentials(ctx, tx, admindriver.ClientCredentials{
				ClientID:   in.ClientID,
				ProjectID:  in.ProjectID,
				CreatedAt:  now,
				UpdatedAt:  now,
				SecretHash: in.SecretHash,
			})
			if err != nil {
				return err
			}
		}
		out = types.Client{
			ID:                   client.ID,
			ProjectID:            client.ProjectID,
			CreatedAt:            client.CreatedAt,
			UpdatedAt:            client.UpdatedAt,
			DisplayName:          client.DisplayName,
			Type:                 types.ClientType(client.Type),
			OrganizationInternal: client.OrganizationInternal,
			Alias:                in.Alias,
		}
		return nil
	})
	if err != nil {
		return types.Client{}, err
	}

	return out, nil
}

// GetClientQuery is a query structure used to get a client.
type GetClientQuery struct {
	// ProjectID is the project identifier of the client.
	ProjectID string `field_behavior:"REQUIRED"`

	// ClientIdentifier is the unique identifier of the client.
	// It may also be an alias (if the client has an alias).
	ClientIdentifier string `field_behavior:"REQUIRED"`
}

// GetClient gets a single client that matches the given query.
func (c *ClientsStorage) GetClient(ctx context.Context, in GetClientQuery) (types.Client, error) {
	var out types.Client
	err := c.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		client, err := c.d.GetClient(ctx, tx, admindriver.GetClient{
			ProjectID:        in.ProjectID,
			ClientIdentifier: in.ClientIdentifier,
		})
		if err != nil {
			return err
		}

		out = types.Client{
			ID:                   client.ID,
			ProjectID:            client.ProjectID,
			CreatedAt:            client.CreatedAt,
			UpdatedAt:            client.UpdatedAt,
			DisplayName:          client.DisplayName,
			Type:                 types.ClientType(client.Type),
			OrganizationInternal: client.OrganizationInternal,
		}
		return nil
	})
	if err != nil {
		return types.Client{}, err
	}

	return out, nil
}
