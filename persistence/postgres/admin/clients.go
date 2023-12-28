// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package postgresadmin

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log/slog"
	"strings"

	admindriver "github.com/blockysource/authz/persistence/driver/admin"
	"github.com/blockysource/authz/persistence/internal/purge"
)

func init() {
	clientInsertQuery = purge.SanitizeSQL(clientInsertQuery)
	clientGetQuery = purge.SanitizeSQL(clientGetQuery)
	clientAliasInsertQuery = purge.SanitizeSQL(clientAliasInsertQuery)
	clientIdentifierInsertQuery = purge.SanitizeSQL(clientIdentifierInsertQuery)
	clientSigningAlgorithmInsertQuery = purge.SanitizeSQL(clientSigningAlgorithmInsertQuery)
	clientSigningAlgorithmBatchInsertQuery = purge.SanitizeSQL(clientSigningAlgorithmBatchInsertQuery)
	clientSigningAlgorithmListQuery = purge.SanitizeSQL(clientSigningAlgorithmListQuery)
	clientCredentialsInsertQuery = purge.SanitizeSQL(clientCredentialsInsertQuery)
	clientResourcePermissionInsertQuery = purge.SanitizeSQL(clientResourcePermissionInsertQuery)
}

var _ admindriver.ClientsStorage = (*ClientStorage)(nil)

// ClientStorage is a postgres client storage used for admin 'authz' service purpose.
type ClientStorage struct {
	log *slog.Logger
}

// NewClientStorage creates a new instance of the ClientStorage.
func NewClientStorage(log *slog.Logger) *ClientStorage {
	return &ClientStorage{
		log: log.With(slog.String("dialect", "postgres")),
	}
}

//go:embed queries/clients/client_insert.sql
var clientInsertQuery string

// InsertClient inserts a client.
// It is part of admindriver.ClientsStorage interface implementation.
func (c *ClientStorage) InsertClient(ctx context.Context, tx *sql.Tx, in admindriver.Client) error {
	_, err := tx.ExecContext(ctx, clientInsertQuery,
		in.ID,
		in.ProjectID,
		in.Type,
		in.CreatedAt,
		in.UpdatedAt,
		in.DisplayName,
		in.OrganizationInternal,
	)
	if err != nil {
		return err
	}

	return nil
}

//go:embed queries/clients/client_get.sql
var clientGetQuery string

// GetClient gets a single client by given query.
func (c *ClientStorage) GetClient(ctx context.Context, tx *sql.Tx, query admindriver.GetClient) (admindriver.Client, error) {
	var out admindriver.Client
	err := tx.QueryRowContext(ctx, clientGetQuery,
		query.ProjectID,
		query.ClientIdentifier,
	).Scan(
		&out.ID,
		&out.ProjectID,
		&out.Type,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.DisplayName,
		&out.OrganizationInternal,
	)
	if err != nil {
		return admindriver.Client{}, err
	}

	return out, nil
}

//go:embed queries/clients/alias_insert.sql
var clientAliasInsertQuery string

// InsertClientAlias inserts a client alias.
// It is part of admindriver.ClientsStorage interface implementation.
func (c *ClientStorage) InsertClientAlias(ctx context.Context, tx *sql.Tx, in admindriver.ClientAlias) error {
	_, err := tx.ExecContext(ctx, clientAliasInsertQuery,
		in.ClientID,
		in.ProjectID,
		in.Alias,
	)
	if err != nil {
		return err
	}

	return nil
}

//go:embed queries/clients/identifier_insert.sql
var clientIdentifierInsertQuery string

// InsertClientIdentifier inserts a client identifier.
// It is part of admindriver.ClientsStorage interface implementation.
func (c *ClientStorage) InsertClientIdentifier(ctx context.Context, tx *sql.Tx, in admindriver.ClientIdentifier) error {
	_, err := tx.ExecContext(ctx, clientIdentifierInsertQuery,
		in.ClientID,
		in.ProjectID,
		in.Identifier,
	)
	if err != nil {
		return err
	}

	return nil
}

//go:embed queries/clients/signing_algorithm_insert.sql
var clientSigningAlgorithmInsertQuery string

// InsertClientSigningAlgorithm inserts a client signing algorithm.
func (c *ClientStorage) InsertClientSigningAlgorithm(ctx context.Context, tx *sql.Tx, in admindriver.ClientSigningAlgorithm) error {
	_, err := tx.ExecContext(ctx, clientSigningAlgorithmInsertQuery,
		in.ClientID,
		in.Algorithm,
		in.Priority,
	)
	if err != nil {
		return err
	}

	return nil
}

//go:embed queries/clients/signing_algorithm_batch_insert.sql
var clientSigningAlgorithmBatchInsertQuery string

// BatchInsertClientSigningAlgorithm inserts a client signing algorithm.
func (c *ClientStorage) BatchInsertClientSigningAlgorithm(ctx context.Context, tx *sql.Tx, in []admindriver.ClientSigningAlgorithm) error {
	if len(in) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString(clientSigningAlgorithmBatchInsertQuery)

	args := make([]any, 0, len(in)*3)
	for i, csa := range in {
		sb.WriteString(fmt.Sprintf(", ($%d, $%d, $%d)", i*3+1, i*3+2, i*3+3))
		args = append(args, csa.ClientID, csa.Algorithm, csa.Priority)
	}

	_, err := tx.ExecContext(ctx, sb.String(), args...)
	if err != nil {
		return err
	}
	return nil
}

//go:embed queries/clients/signing_algorithm_list.sql
var clientSigningAlgorithmListQuery string

// ListClientSigningAlgorithms lists client signing algorithms.
func (c *ClientStorage) ListClientSigningAlgorithms(ctx context.Context, tx *sql.Tx, query admindriver.ClientSigningAlgorithmsQuery) ([]admindriver.ClientSigningAlgorithm, error) {
	var out []admindriver.ClientSigningAlgorithm
	rows, err := tx.QueryContext(ctx, clientSigningAlgorithmListQuery,
		query.ProjectID,
		query.ClientID,
	)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var alg admindriver.ClientSigningAlgorithm
		err = rows.Scan(
			&alg.ClientID,
			&alg.Algorithm,
			&alg.Priority,
		)
		if err != nil {
			return nil, err
		}

		out = append(out, alg)
	}

	return out, nil
}

//go:embed queries/clients/signing_algorithm_batch_delete.sql
var clientSigningAlgorithmBatchDeleteQuery string

// BatchDeleteClientSigningAlgorithm deletes client signing algorithms.
func (c *ClientStorage) BatchDeleteClientSigningAlgorithm(ctx context.Context, tx *sql.Tx, query admindriver.ClientSigningAlgorithmsQuery) error {
	_, err := tx.ExecContext(ctx, clientSigningAlgorithmBatchDeleteQuery,
		query.ProjectID,
		query.ClientID,
	)
	if err != nil {
		return err
	}

	return nil
}

//go:embed queries/clients/credentials_insert.sql
var clientCredentialsInsertQuery string

// InsertClientCredentials inserts a client credentials.
func (c *ClientStorage) InsertClientCredentials(ctx context.Context, tx *sql.Tx, in admindriver.ClientCredentials) error {
	_, err := tx.ExecContext(ctx, clientCredentialsInsertQuery,
		in.ClientID,
		in.SecretHash,
		in.CreatedAt,
	)
	if err != nil {
		return err
	}

	return nil
}

//go:embed queries/clients/resource_permission_insert.sql
var clientResourcePermissionInsertQuery string

// InsertClientResourcePermission inserts a client permission.
func (c *ClientStorage) InsertClientResourcePermission(ctx context.Context, tx *sql.Tx, in admindriver.ClientResourcePermission) error {
	_, err := tx.ExecContext(ctx, clientResourcePermissionInsertQuery,
		in.ClientID,
		in.ResourcePermissionID,
		in.ProjectID,
	)
	if err != nil {
		return err
	}

	return nil
}
