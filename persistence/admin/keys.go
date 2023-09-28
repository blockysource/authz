// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"gocloud.dev/pubsub"
	"gocloud.dev/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/blockysource/authz/deps"
	"github.com/blockysource/authz/keys"
	admindriver "github.com/blockysource/authz/persistence/driver/admin"
	"github.com/blockysource/authz/persistence/driver/algorithm"
	uuid "github.com/blockysource/authz/persistence/driver/uuid"
	"github.com/blockysource/authz/types"
	"github.com/blockysource/blocky-aip/expr"
	"github.com/blockysource/blockysql"
	"github.com/blockysource/blockysql/bserr"
	authzeventsv1alpha "github.com/blockysource/go-genproto/blocky/authz/events/v1alpha"
)

// KeysStorage represents the keys admin storage interface.
type KeysStorage struct {
	d       admindriver.KeysStorage
	db      *blockysql.DB
	topics  *deps.Topics
	secrets *secrets.Keeper
	kg      keys.Generator
	log     slog.Logger
}

func (s *KeysStorage) revisionCreated() *pubsub.Topic {
	return s.topics.KeyRevisionCreated
}
func (s *KeysStorage) revisionRevoked() *pubsub.Topic {
	return s.topics.KeyRevisionRevoked
}

// CreateKeyQuery is a query for creating a key.
type CreateKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// DisplayName is the display name of the key.
	DisplayName string

	// Algorithm is the signing algorithm of the key.
	Algorithm types.SigningAlgorithm

	// RotationPeriod is the rotation period of the key.
	RotationPeriod time.Duration

	// Priority is the priority of the key.
	Priority int
}

// CreateKey creates a new key in the database.
func (s *KeysStorage) CreateKey(ctx context.Context, in CreateKeyQuery) (types.Key, error) {
	keyID := uuid.New()
	key := types.Key{
		ID:             keyID.String(),
		ProjectID:      in.ProjectID,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		DisplayName:    in.DisplayName,
		Algorithm:      algorithm.SigningAlgorithm(in.Algorithm),
		RotationPeriod: in.RotationPeriod,
		Priority:       in.Priority,
	}
	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		err := s.d.CreateKey(ctx, tx, admindriver.Key{
			ID:             keyID,
			ProjectID:      key.ProjectID,
			CreatedAt:      key.CreatedAt,
			UpdatedAt:      key.UpdatedAt,
			DisplayName:    key.DisplayName,
			Algorithm:      key.Algorithm,
			RotationPeriod: key.RotationPeriod,
			Priority:       key.Priority,
		})
		if err != nil {
			return err
		}

		// Insert key identifier.
		err = s.d.InsertKeyIdentifier(ctx, tx, admindriver.KeyIdentifier{
			KeyID:     keyID,
			ProjectID: key.ProjectID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		s.log.Error("failed to create key", err)
		return types.Key{}, status.Error(codes.Internal, "failed to create key")
	}
	return key, nil
}

// GetKey gets a key from the database.
func (s *KeysStorage) GetKey(ctx context.Context, projectID, keyID string) (types.Key, error) {
	var key admindriver.Key

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		key, err = s.d.GetKey(ctx, nil, admindriver.GetKeyQuery{
			ProjectID:     projectID,
			KeyIdentifier: keyID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return types.Key{}, err
	}
	return types.Key{
		ID:             key.ID.String(),
		ProjectID:      key.ProjectID,
		CreatedAt:      key.CreatedAt,
		UpdatedAt:      key.UpdatedAt,
		DisplayName:    key.DisplayName,
		Algorithm:      key.Algorithm,
		RotationPeriod: key.RotationPeriod,
		Priority:       key.Priority,
		Revisions:      key.Revisions,
		LastRotatedAt:  key.LastRotatedAt.Time,
	}, nil
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

// ListKeysResult is a result of listing keys.
type ListKeysResult struct {
	// Keys is the list of keys.
	Keys []types.Key

	// Total is the total count of the keys.
	Total int64
}

// ListKeys lists keys from the database.
func (s *KeysStorage) ListKeys(ctx context.Context, in ListKeysQuery) (ListKeysResult, error) {
	var (
		listedKeys []admindriver.Key
		out        ListKeysResult
	)

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		listedKeys, err = s.d.ListKeys(ctx, tx, admindriver.ListKeysQuery{
			ProjectID: in.ProjectID,
			PageSize:  in.PageSize,
			Skip:      in.Skip,
			OrderBy:   in.OrderBy,
			Filter:    in.Filter,
		})
		if err != nil {
			return err
		}

		// Get total count.
		out.Total, err = s.d.CountKeys(ctx, tx, admindriver.CountKeysQuery{
			ProjectID: in.ProjectID,
			Filter:    in.Filter,
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return out, err
	}

	outKeys := make([]types.Key, len(listedKeys))
	for i, key := range listedKeys {
		outKeys[i] = types.Key{
			ID:             key.ID.String(),
			ProjectID:      key.ProjectID,
			CreatedAt:      key.CreatedAt,
			UpdatedAt:      key.UpdatedAt,
			DisplayName:    key.DisplayName,
			Algorithm:      key.Algorithm,
			RotationPeriod: key.RotationPeriod,
			Priority:       key.Priority,
			Revisions:      key.Revisions,
			LastRotatedAt:  key.LastRotatedAt.Time,
		}
	}

	out.Keys = outKeys

	return out, nil
}

// UpdateKeyQuery is a query for updating a key.
type UpdateKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyID is the identifier of the key.
	KeyID string

	// Expr is the update expression of the key.
	Expr *expr.UpdateExpr
}

// UpdateKey updates a key in the database.
func (s *KeysStorage) UpdateKey(ctx context.Context, in UpdateKeyQuery) (types.Key, error) {
	var key admindriver.Key

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		err := s.d.UpdateKey(ctx, tx, admindriver.UpdateKeyQuery{
			ProjectID:     in.ProjectID,
			KeyIdentifier: in.KeyID,
			Expr:          in.Expr,
		})
		if err != nil {
			return err
		}

		key, err = s.d.GetKey(ctx, tx, admindriver.GetKeyQuery{
			ProjectID:     in.ProjectID,
			KeyIdentifier: in.KeyID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		switch s.db.ErrorCode(err) {
		case bserr.NotFound:
			return types.Key{}, status.Error(codes.NotFound, "key not found")
		case bserr.ConstraintViolation:
			s.log.Debug("failed to update key", err)
			return types.Key{}, status.Error(codes.InvalidArgument, "violated key constraint")
		}
		s.log.Error("failed to update key", err)
		return types.Key{}, status.Error(codes.Internal, "failed to update key")
	}
	return types.Key{
		ID:             key.ID.String(),
		ProjectID:      key.ProjectID,
		CreatedAt:      key.CreatedAt,
		UpdatedAt:      key.UpdatedAt,
		DisplayName:    key.DisplayName,
		Algorithm:      key.Algorithm,
		RotationPeriod: key.RotationPeriod,
		Priority:       key.Priority,
		Revisions:      key.Revisions,
		LastRotatedAt:  key.LastRotatedAt.Time,
	}, nil
}

// CreateKeyRevisionQuery is a query for creating a key revision.
type CreateKeyRevisionQuery struct {
	ProjectID string
	KeyID     string
}

// CreateKeyRevision creates a new key revision in the database.
func (s *KeysStorage) CreateKeyRevision(ctx context.Context, in CreateKeyRevisionQuery) (types.KeyRevision, error) {
	var kv types.KeyRevision

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		// Get the parent key in a locked state. This lock is working as a mutex for the key.
		k, err := s.d.GetAndLockKey(ctx, tx, admindriver.GetKeyQuery{ProjectID: in.ProjectID, KeyIdentifier: in.KeyID})
		if err != nil {
			return err
		}

		// Generate a new key revision.
		sk, err := s.kg.GenerateSigningKey(k.ID.String(), k.Priority,types.SigningAlgorithm(k.Algorithm))
		if err != nil {
			return err
		}

		// Set up identifiers on the key revision.
		kv.ID = sk.RevisionID
		kv.ProjectID = k.ProjectID
		kv.KeyID = k.ID.String()

		// Get the binary form of the private key.
		privateKey, err := sk.MarshalBinary()
		if err != nil {
			return err
		}

		// Encrypt the private key binary.
		enc, err := s.secrets.Encrypt(ctx, privateKey)
		if err != nil {
			return err
		}

		// Create the key revision timstamp.
		now := time.Now().Truncate(time.Millisecond)

		// Create the key revision.
		err = s.d.CreateKeyRevision(ctx, tx, admindriver.KeyRevision{
			ID:              sk.RevisionID,
			KeyID:           k.ID,
			ProjectID:       kv.ProjectID,
			CreatedAt:       now,
			Priority:        k.Priority,
			EncryptedSecret: enc,
			Revision:        k.Revisions + 1,
		})
		if err != nil {
			return err
		}
		kv.CreatedAt = now
		kv.Revision = k.Revisions + 1

		// Insert key revision identifier.
		err = s.d.InsertKeyRevisionIdentifier(ctx, tx, admindriver.KeyRevisionIdentifier{
			KeyRevisionID: kv.ID,
			KeyID:         k.ID,
			Identifier:    kv.ID,
		})
		if err != nil {
			return err
		}

		// Update the latest key revision identifier.
		if k.Revisions > 0 {
			err = s.d.UpdateLatestKeyRevisionIdentifier(ctx, tx, admindriver.UpdateLatestKeyRevisionIdentifier{
				KeyID:         k.ID,
				KeyRevisionID: kv.ID,
			})
		} else {
			err = s.d.InsertKeyRevisionIdentifier(ctx, tx, admindriver.KeyRevisionIdentifier{
				KeyID:         k.ID,
				KeyRevisionID: kv.ID,
				Identifier:    "latest",
			})
		}

		// Insert key revision number as an alias.
		err = s.d.InsertKeyRevisionIdentifier(ctx, tx, admindriver.KeyRevisionIdentifier{
			KeyRevisionID: kv.ID,
			KeyID:         k.ID,
			Identifier:    strconv.Itoa(kv.Revision),
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		ec := s.db.ErrorCode(err)
		switch ec {
		case bserr.NotFound:
			return types.KeyRevision{}, status.Error(codes.NotFound, "key not found")
		}

		s.log.Error("failed to create key revision", err)
		return types.KeyRevision{}, status.Error(codes.Internal, "failed to create key revision")
	}

	revision, err2, done := s.notifyRevisionCreated(ctx, kv)
	if done {
		return revision, err2
	}
	return kv, nil
}

func (s *KeysStorage) notifyRevisionCreated(ctx context.Context, kv types.KeyRevision) (types.KeyRevision, error, bool) {
	// Compose key revision created event.
	e := authzeventsv1alpha.KeyRevisionCreated{
		Name: string(types.ComposeKeyRevisionName(kv.ProjectID, kv.KeyID, kv.ID)),

	}

	// Marshal the message to the protobuf format.
	md, err := proto.Marshal(&e)
	if err != nil {
		s.log.Error("failed to marshal event", err)
		return types.KeyRevision{}, status.Error(codes.Internal, "failed to marshal event"), true
	}

	// Send the message to the topic asynchronously.
	msg := pubsub.Message{Body: md}
	if err = s.revisionCreated().Send(ctx, &msg); err != nil {
		s.log.Error("failed to send event", err)
	}
	return types.KeyRevision{}, nil, false
}

func (s *KeysStorage) newKeyRevisionID() (string, error) {
	keyIDBytes := make([]byte, 20)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(keyIDBytes), nil
}

// GetKeyRevisionQuery is a query for getting a key revision.
type GetKeyRevisionQuery struct {
	// ProjectID is the project identifier of the key revision.
	ProjectID string

	// KeyID is the identifier of the key revision.
	KeyID string

	// KeyRevisionID is the identifier of the key revision.
	KeyRevisionID string
}

// GetKeyRevision gets a key revision from the database.
func (s *KeysStorage) GetKeyRevision(ctx context.Context, in GetKeyRevisionQuery) (types.KeyRevision, error) {
	var keyRevision admindriver.KeyRevision

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		keyRevision, err = s.d.GetKeyRevision(ctx, tx, admindriver.GetKeyRevisionQuery{
			ProjectID:             in.ProjectID,
			KeyIdentifier:         in.KeyID,
			KeyRevisionIdentifier: in.KeyRevisionID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		switch s.db.ErrorCode(err) {
		case bserr.NotFound:
			return types.KeyRevision{}, status.Error(codes.NotFound, "key revision not found")
		}
		s.log.Error("failed to get key revision", err)
		return types.KeyRevision{}, status.Error(codes.Internal, "failed to get key revision")
	}
	return types.KeyRevision{
		ID:        keyRevision.ID,
		KeyID:     keyRevision.KeyID.String(),
		ProjectID: keyRevision.ProjectID,
		CreatedAt: keyRevision.CreatedAt,
		RevokedAt: keyRevision.RevokedAt.Time,
		Revision:  keyRevision.Revision,
	}, nil
}

// ListKeyRevisionsQuery is a query for listing key revisions.
type ListKeyRevisionsQuery struct {
	// ProjectID is the project identifier of the key revisions.
	ProjectID string

	// KeyID is the identifier of the key revisions.
	KeyID string

	// PageSize is the page size of the key revisions.
	PageSize int

	// Skip is the number of key revisions to skip.
	Skip int

	// OrderBy is the order by expression of the key revisions.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}

// ListKeyRevisionsResult is a result of listing key revisions.
type ListKeyRevisionsResult struct {
	// KeyRevisions is the list of key revisions.
	KeyRevisions []types.KeyRevision

	// Total is the total count of the key revisions.
	Total int64
}

// ListKeyRevisions lists key revisions from the database.
func (s *KeysStorage) ListKeyRevisions(ctx context.Context, in ListKeyRevisionsQuery) (ListKeyRevisionsResult, error) {
	var (
		listedKeyRevisions []admindriver.KeyRevision
		out                ListKeyRevisionsResult
	)

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		listedKeyRevisions, err = s.d.ListKeyRevisions(ctx, tx, admindriver.ListKeyRevisionsQuery{
			ProjectID:     in.ProjectID,
			KeyIdentifier: in.KeyID,
			PageSize:      in.PageSize,
			Skip:          in.Skip,
			OrderBy:       in.OrderBy,
			Filter:        in.Filter,
		})
		if err != nil {
			return err
		}

		// Get total count.
		out.Total, err = s.d.CountKeyRevisions(ctx, tx, admindriver.CountKeyRevisionsQuery{
			ProjectID:     in.ProjectID,
			KeyIdentifier: in.KeyID,
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil
		}

		return nil
	})
	if err != nil {
		s.log.Error("failed to list key revisions", "error", err)
		return out, status.Error(codes.Internal, "failed to list key revisions")
	}

	outKeyRevisions := make([]types.KeyRevision, len(listedKeyRevisions))
	for i, keyRevision := range listedKeyRevisions {
		outKeyRevisions[i] = types.KeyRevision{
			ID:        keyRevision.ID,
			KeyID:     keyRevision.KeyID.String(),
			ProjectID: keyRevision.ProjectID,
			CreatedAt: keyRevision.CreatedAt,
			RevokedAt: keyRevision.RevokedAt.Time,
			Revision:  keyRevision.Revision,
		}
	}

	out.KeyRevisions = outKeyRevisions

	return out, nil
}

// RevokeKeyRevisionQuery is a query for revoking a key revision.
type RevokeKeyRevisionQuery struct {
	// ProjectID is the project identifier of the key revision.
	ProjectID string

	// KeyIdentifier is the identifier of the key revision.
	KeyIdentifier string

	// RevisionIdentifier is the identifier of the key revision.
	RevisionIdentifier string
}

// RevokeKeyRevision revokes a key revision in the database.
func (s *KeysStorage) RevokeKeyRevision(ctx context.Context, in RevokeKeyRevisionQuery) (types.KeyRevision, error) {
	var (
		rev            admindriver.KeyRevision
		alreadyRevoked bool
	)

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		// Get the key revision.
		var err error
		rev, err = s.d.GetKeyRevision(ctx, tx, admindriver.GetKeyRevisionQuery{
			ProjectID:             in.ProjectID,
			KeyIdentifier:         in.KeyIdentifier,
			KeyRevisionIdentifier: in.RevisionIdentifier,
		})
		if err != nil {
			return err
		}

		// Check if it was already revoked.
		if rev.RevokedAt.Valid {
			alreadyRevoked = true
			return nil
		}

		// Revoke the key revision.
		now := time.Now().Truncate(time.Millisecond)
		rev.RevokedAt = sql.NullTime{
			Time:  now,
			Valid: true,
		}
		err = s.d.RevokeKeyRevision(ctx, tx, admindriver.RevokeKeyRevisionQuery{
			ProjectID:          in.ProjectID,
			KeyIdentifier:      rev.KeyID.String(),
			RevisionIdentifier: in.RevisionIdentifier,
			RevokedAt:          now,
		})
		if err != nil {
			return err
		}

		return nil
	})

	// Check if any error occurred during the transaction.
	if err != nil {
		switch s.db.ErrorCode(err) {
		case bserr.NotFound:
			return types.KeyRevision{}, status.Error(codes.NotFound, "key revision not found")
		}
		s.log.Error("failed to revoke key revision", err)
		return types.KeyRevision{}, status.Error(codes.Internal, "failed to revoke key revision")
	}

	// Check if the key revision was already revoked, if so, return a failed precondition error.
	if alreadyRevoked {
		return types.KeyRevision{}, status.Error(codes.FailedPrecondition, "key revision already revoked")
	}

	// Send the key revision revoked event.
	revName := types.ComposeKeyRevisionName(rev.ProjectID, rev.KeyID.String(), rev.ID)
	if err = s.notifyRevisionRevoked(ctx, revName); err != nil {
		s.log.Error("failed to notify key revision revoked", "error", err)
	}

	return types.KeyRevision{
		ID:        rev.ID,
		KeyID:     rev.KeyID.String(),
		ProjectID: rev.ProjectID,
		CreatedAt: rev.CreatedAt,
		RevokedAt: rev.RevokedAt.Time,
		Revision:  rev.Revision,
	}, nil
}

func (s *KeysStorage) notifyRevisionRevoked(ctx context.Context, name types.KeyRevisionName) error {
	// Compose key revision revoked event.
	e := authzeventsv1alpha.KeyRevisionRevoked{
		Name: string(name),
	}

	// Marshal the message to the protobuf format.
	md, err := proto.Marshal(&e)
	if err != nil {
		return err
	}

	// Send the message to the topic asynchronously.
	msg := pubsub.Message{Body: md}
	if err = s.revisionRevoked().Send(ctx, &msg); err != nil {
		return err
	}
	return nil
}
