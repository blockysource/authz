// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admindb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/blockysource/authz/logic/keys"
	postgresadmin "github.com/blockysource/authz/persistence/postgres/admin"
	"github.com/blockysource/blockysql/driver"
	"log/slog"
	"strconv"
	"time"

	"gocloud.dev/pubsub"
	"gocloud.dev/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/blockysource/authz/deps"
	admindriver "github.com/blockysource/authz/persistence/driver/admin"
	"github.com/blockysource/authz/persistence/driver/algorithmdb"
	uuid "github.com/blockysource/authz/persistence/driver/uuid"
	"github.com/blockysource/authz/types"
	"github.com/blockysource/authz/types/algorithm"
	"github.com/blockysource/blocky-aip/expr"
	"github.com/blockysource/blockysql"
	"github.com/blockysource/blockysql/bserr"
	authzunsafeeventsv1alpha "github.com/blockysource/go-genproto/blocky/authz/unsafe/events/v1alpha"
)

// KeysStorage represents the keys admin storage interface.
type KeysStorage struct {
	d       admindriver.KeysStorage
	db      *blockysql.DB
	topics  *deps.Topics
	secrets *secrets.Keeper
	log     *slog.Logger
}

// NewKeysStorage creates a new keys admin storage.
func NewKeysStorage(d *deps.Dependencies) (*KeysStorage, error) {
	logger := slog.New(d.Logger).With(
		slog.String("service", "authz"),
		slog.String("component", "admin"),
		slog.String("storage", "keys"),
	)

	var drv admindriver.KeysStorage
	switch d.DB.Dialect() {
	case driver.DialectPostgres:
		drv = postgresadmin.NewKeysStorage(logger)
	default:
		return nil, errors.New("blockysql: unsupported dialect")
	}

	ks := &KeysStorage{
		d:       drv,
		db:      d.DB,
		topics:  &d.Topics,
		secrets: d.KeySecretKeeper,
		log:     logger,
	}
	return ks, nil
}

func (s *KeysStorage) keyCreated() *pubsub.Topic {
	return s.topics.KeyCreated
}
func (s *KeysStorage) keyRevoked() *pubsub.Topic {
	return s.topics.KeyRevoked
}

// CreateKeyCoreQuery is a query for creating a key.
type CreateKeyCoreQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// DisplayName is the display name of the key.
	DisplayName string

	// Algorithm is the signing algorithm of the key.
	Algorithm algorithm.SigningAlgorithm

	// RotationInterval is the rotation period of the key.
	RotationInterval time.Duration

	// Priority is the priority of the key.
	Priority int
}

// CreateKeyCore creates a new key in the database.
func (s *KeysStorage) CreateKeyCore(ctx context.Context, in CreateKeyCoreQuery) (types.KeyCore, error) {
	keyCoreID := uuid.New()
	keyCore := types.KeyCore{
		ID:               keyCoreID.String(),
		ProjectID:        in.ProjectID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		DisplayName:      in.DisplayName,
		Algorithm:        algorithmdb.SigningAlgorithm(in.Algorithm),
		RotationInterval: in.RotationInterval,
		Priority:         in.Priority,
	}
	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		err := s.d.CreateKeyCore(ctx, tx, admindriver.KeyCore{
			ID:               keyCoreID,
			ProjectID:        keyCore.ProjectID,
			CreatedAt:        keyCore.CreatedAt,
			UpdatedAt:        keyCore.UpdatedAt,
			DisplayName:      keyCore.DisplayName,
			Algorithm:        keyCore.Algorithm,
			RotationInterval: keyCore.RotationInterval,
			Priority:         keyCore.Priority,
		})
		if err != nil {
			return err
		}

		// Insert key identifier.
		err = s.d.InsertKeyCoreIdentifier(ctx, tx, admindriver.KeyCoreIdentifier{
			KeyCoreID: keyCoreID,
			ProjectID: keyCore.ProjectID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		s.log.Error("failed to create key core", err)
		return types.KeyCore{}, status.Error(codes.Internal, "failed to create key core")
	}
	return keyCore, nil
}

// GetKeyCore gets a key from the database.
func (s *KeysStorage) GetKeyCore(ctx context.Context, projectID, keyCoreID string) (types.KeyCore, error) {
	var keyCore admindriver.KeyCore

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		keyCore, err = s.d.GetKeyCore(ctx, nil, admindriver.GetKeyCoreQuery{
			ProjectID:         projectID,
			KeyCoreIdentifier: keyCoreID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return types.KeyCore{}, err
	}
	return types.KeyCore{
		ID:               keyCore.ID.String(),
		ProjectID:        keyCore.ProjectID,
		CreatedAt:        keyCore.CreatedAt,
		UpdatedAt:        keyCore.UpdatedAt,
		DisplayName:      keyCore.DisplayName,
		Algorithm:        keyCore.Algorithm,
		RotationInterval: keyCore.RotationInterval,
		Priority:         keyCore.Priority,
		DerivedKeysCount: keyCore.DerivedKeysCount,
		LastRotatedAt:    keyCore.LastRotatedAt.Time,
	}, nil
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

// ListKeyCoresResult is a result of listing keys.
type ListKeyCoresResult struct {
	// KeyCores is the list of keys.
	KeyCores []types.KeyCore

	// Total is the total count of the keys.
	Total int64
}

// ListKeyCores lists keys from the database.
func (s *KeysStorage) ListKeyCores(ctx context.Context, in ListKeyCoresQuery) (ListKeyCoresResult, error) {
	var (
		listedKeys []admindriver.KeyCore
		out        ListKeyCoresResult
	)

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		listedKeys, err = s.d.ListKeyCores(ctx, tx, admindriver.ListKeyCoresQuery{
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
		out.Total, err = s.d.CountKeyCores(ctx, tx, admindriver.CountKeyCoresQuery{
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

	outKeys := make([]types.KeyCore, len(listedKeys))
	for i, key := range listedKeys {
		outKeys[i] = types.KeyCore{
			ID:               key.ID.String(),
			ProjectID:        key.ProjectID,
			CreatedAt:        key.CreatedAt,
			UpdatedAt:        key.UpdatedAt,
			DisplayName:      key.DisplayName,
			Algorithm:        key.Algorithm,
			RotationInterval: key.RotationInterval,
			Priority:         key.Priority,
			DerivedKeysCount: key.DerivedKeysCount,
			LastRotatedAt:    key.LastRotatedAt.Time,
		}
	}

	out.KeyCores = outKeys

	return out, nil
}

// UpdateKeyCoreQuery is a query for updating a key.
type UpdateKeyCoreQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyCoreID is the identifier of the key.
	KeyCoreID string

	// Expr is the update expression of the key.
	Expr *expr.UpdateExpr
}

// UpdateKeyCore updates a key in the database.
func (s *KeysStorage) UpdateKeyCore(ctx context.Context, in UpdateKeyCoreQuery) (types.KeyCore, error) {
	var key admindriver.KeyCore

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		err := s.d.UpdateKeyCore(ctx, tx, admindriver.UpdateKeyCoreQuery{
			ProjectID:         in.ProjectID,
			KeyCoreIdentifier: in.KeyCoreID,
			Expr:              in.Expr,
		})
		if err != nil {
			return err
		}

		key, err = s.d.GetKeyCore(ctx, tx, admindriver.GetKeyCoreQuery{
			ProjectID:         in.ProjectID,
			KeyCoreIdentifier: in.KeyCoreID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		switch s.db.ErrorCode(err) {
		case bserr.NotFound:
			return types.KeyCore{}, status.Error(codes.NotFound, "key core not found")
		case bserr.ConstraintViolation:
			s.log.Debug("failed to update key core", err)
			return types.KeyCore{}, status.Error(codes.InvalidArgument, "violated key core constraint")
		}
		s.log.Error("failed to update key core", err)
		return types.KeyCore{}, status.Error(codes.Internal, "failed to update key core")
	}
	return types.KeyCore{
		ID:               key.ID.String(),
		ProjectID:        key.ProjectID,
		CreatedAt:        key.CreatedAt,
		UpdatedAt:        key.UpdatedAt,
		DisplayName:      key.DisplayName,
		Algorithm:        key.Algorithm,
		RotationInterval: key.RotationInterval,
		Priority:         key.Priority,
		DerivedKeysCount: key.DerivedKeysCount,
		LastRotatedAt:    key.LastRotatedAt.Time,
	}, nil
}

// RotateKeyQuery is a query for creating a key revision.
type RotateKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyCoreIdentifier is the identifier of the key.
	KeyCoreIdentifier string

	// KeyGenerator is the key generator.
	KeyGenerator keys.SigningKeyGenerator
}

// RotateKey creates a new key revision in the database.
func (s *KeysStorage) RotateKey(ctx context.Context, in RotateKeyQuery) (types.Key, error) {
	var key types.Key

	if in.KeyGenerator == nil {
		s.log.ErrorContext(ctx, "key generator is not defined")
		return types.Key{}, status.Error(codes.Internal, "internal error")
	}

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		// Get the parent key in a locked state. This lock is working as a mutex for the key.
		keyCore, err := s.d.GetAndLockKeyCore(ctx, tx, admindriver.GetKeyCoreQuery{ProjectID: in.ProjectID, KeyCoreIdentifier: in.KeyCoreIdentifier})
		if err != nil {
			return err
		}

		// Generate a new key revision.
		sk, err := in.KeyGenerator.GenerateSigningKey(keyCore.ID.String(), keyCore.Priority, algorithm.SigningAlgorithm(keyCore.Algorithm))
		if err != nil {
			return err
		}

		// Set up identifiers on the key revision.
		key.ID = sk.KeyID
		key.ProjectID = keyCore.ProjectID
		key.CoreID = keyCore.ID.String()

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
		err = s.d.CreateKey(ctx, tx, admindriver.KeyWithSecret{
			ID:              sk.KeyID,
			CoreID:          keyCore.ID,
			ProjectID:       key.ProjectID,
			CreatedAt:       now,
			Priority:        keyCore.Priority,
			EncryptedSecret: enc,
			Revision:        keyCore.DerivedKeysCount + 1,
		})
		if err != nil {
			return err
		}
		key.CreatedAt = now
		key.Revision = keyCore.DerivedKeysCount + 1

		// Insert key revision identifier.
		err = s.d.InsertCoreKeyIdentifier(ctx, tx, admindriver.CoreKeyIdentifier{
			KeyID:      key.ID,
			CoreID:     keyCore.ID,
			Identifier: key.ID,
		})
		if err != nil {
			return err
		}

		// Update the latest key revision identifier.
		if keyCore.DerivedKeysCount > 0 {
			err = s.d.UpdateLatestCoreKeyIdentifier(ctx, tx, admindriver.UpdateLatestCoreKeyIdentifier{
				CoreID: keyCore.ID,
				KeyID:  key.ID,
			})
		} else {
			err = s.d.InsertCoreKeyIdentifier(ctx, tx, admindriver.CoreKeyIdentifier{
				CoreID:     keyCore.ID,
				KeyID:      key.ID,
				Identifier: "latest",
			})
		}

		// Insert key revision number as an alias.
		err = s.d.InsertCoreKeyIdentifier(ctx, tx, admindriver.CoreKeyIdentifier{
			KeyID:      key.ID,
			CoreID:     keyCore.ID,
			Identifier: strconv.Itoa(key.Revision),
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
			return types.Key{}, status.Error(codes.NotFound, "key not found")
		}

		s.log.Error("failed to rotate key", err)
		return types.Key{}, status.Error(codes.Internal, "failed to rotate key")
	}

	if err = s.notifyKeyRotated(ctx, key); err != nil {
		s.log.Error("failed to notify key rotated", err)
	}
	return key, nil
}

func (s *KeysStorage) notifyKeyRotated(ctx context.Context, k types.Key) error {
	// Compose key revision created event.
	e := authzunsafeeventsv1alpha.KeyRotated{
		Name: string(types.ComposeKeyName(k.ProjectID, k.ID)),
	}

	// Marshal the message to the protobuf format.
	md, err := proto.Marshal(&e)
	if err != nil {
		s.log.Error("failed to marshal event", err)
		return status.Error(codes.Internal, "failed to marshal event")
	}

	// Send the message to the topic asynchronously.
	msg := pubsub.Message{Body: md}
	if err = s.keyCreated().Send(ctx, &msg); err != nil {
		s.log.Error("failed to send event", err)
	}
	return nil
}

func (s *KeysStorage) newKeyRevisionID() (string, error) {
	keyIDBytes := make([]byte, 20)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(keyIDBytes), nil
}

// GetKeyQuery is a query for getting a key revision.
type GetKeyQuery struct {
	// ProjectID is the project identifier of the key revision.
	ProjectID string

	// KeyID is the identifier of the key revision.
	KeyID string
}

// GetKey gets a key revision from the database.
func (s *KeysStorage) GetKey(ctx context.Context, in GetKeyQuery) (types.Key, error) {
	var key admindriver.Key

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		key, err = s.d.GetKey(ctx, tx, admindriver.GetKeyQuery{
			ProjectID: in.ProjectID,
			KeyID:     in.KeyID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		switch s.db.ErrorCode(err) {
		case bserr.NotFound:
			return types.Key{}, status.Error(codes.NotFound, "key revision not found")
		}
		s.log.Error("failed to get key revision", err)
		return types.Key{}, status.Error(codes.Internal, "failed to get key revision")
	}
	return types.Key{
		ID:        key.ID,
		CoreID:    key.CoreID.String(),
		ProjectID: key.ProjectID,
		CreatedAt: key.CreatedAt,
		RevokedAt: key.RevokedAt.Time,
		Revision:  key.Revision,
	}, nil
}

// ListKeysQuery is a query for listing key revisions.
type ListKeysQuery struct {
	// ProjectID is the project identifier of the key revisions.
	ProjectID string

	// CoreID is the identifier of the key core.
	// If it is defined, only keys derived from this core will be listed.
	CoreID string

	// PageSize is the page size of the key revisions.
	PageSize int

	// Skip is the number of key revisions to skip.
	Skip int

	// OrderBy is the order by expression of the key revisions.
	OrderBy *expr.OrderByExpr

	// Filter is the filter expression of the key revisions.
	Filter *expr.FilterExpr
}

// ListKeysResult is a result of listing keys.
type ListKeysResult struct {
	// Keys is the list of keys.
	Keys []types.Key

	// Total is the total count of the keys.
	Total int64
}

// ListKeys lists key revisions from the database.
func (s *KeysStorage) ListKeys(ctx context.Context, in ListKeysQuery) (ListKeysResult, error) {
	var (
		listedKeys []admindriver.Key
		out        ListKeysResult
	)

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		if in.CoreID != "" {
			listedKeys, err = s.d.ListKeyCoreKeys(ctx, tx, admindriver.ListKeyCoreKeysQuery{
				ProjectID:      in.ProjectID,
				CoreIdentifier: in.CoreID,
				PageSize:       in.PageSize,
				Skip:           in.Skip,
				OrderBy:        in.OrderBy,
				Filter:         in.Filter,
			})
			if err != nil {
				return err
			}

			// Get total count.
			out.Total, err = s.d.CountCoreKeys(ctx, tx, admindriver.CountKeyCoreKeysQuery{
				ProjectID:      in.ProjectID,
				CoreIdentifier: in.CoreID,
			})
			if err != nil {
				return err
			}
		} else {
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
			})
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil
			}
		}

		return nil
	})
	if err != nil {
		s.log.Error("failed to list keys", "error", err)
		return out, status.Error(codes.Internal, "failed to list keys")
	}

	outKeyRevisions := make([]types.Key, len(listedKeys))
	for i, keyRevision := range listedKeys {
		outKeyRevisions[i] = types.Key{
			ID:        keyRevision.ID,
			CoreID:    keyRevision.CoreID.String(),
			ProjectID: keyRevision.ProjectID,
			CreatedAt: keyRevision.CreatedAt,
			RevokedAt: keyRevision.RevokedAt.Time,
			Revision:  keyRevision.Revision,
		}
	}

	out.Keys = outKeyRevisions

	return out, nil
}

// RevokeKeyQuery is a query for revoking a key revision.
type RevokeKeyQuery struct {
	// ProjectID is the project identifier of the key.
	ProjectID string

	// KeyID is the identifier of the key.
	KeyID string
}

// RevokeKey revokes a key in the database.
func (s *KeysStorage) RevokeKey(ctx context.Context, in RevokeKeyQuery) (types.Key, error) {
	var (
		key            admindriver.Key
		alreadyRevoked bool
	)

	err := s.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		// Get the key.
		var err error
		key, err = s.d.GetKey(ctx, tx, admindriver.GetKeyQuery{
			ProjectID: in.ProjectID,
			KeyID:     in.KeyID,
		})
		if err != nil {
			return err
		}

		// Check if it was already revoked.
		if key.RevokedAt.Valid {
			alreadyRevoked = true
			return nil
		}

		// Revoke the key.
		now := time.Now().Truncate(time.Millisecond)
		key.RevokedAt = sql.NullTime{
			Time:  now,
			Valid: true,
		}
		err = s.d.RevokeKey(ctx, tx, admindriver.RevokeKeyQuery{
			ProjectID: in.ProjectID,
			KeyID:     in.KeyID,
			RevokedAt: now,
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
			return types.Key{}, status.Error(codes.NotFound, "key not found")
		}
		s.log.Error("failed to revoke key", err)
		return types.Key{}, status.Error(codes.Internal, "failed to revoke key")
	}

	// Check if the key was already revoked, if so, return a failed precondition error.
	if alreadyRevoked {
		return types.Key{}, status.Error(codes.FailedPrecondition, "key already revoked")
	}

	// Send the key revoked event.
	keyName := types.ComposeKeyName(key.ProjectID, key.ID)
	if err = s.notifyKeyRevoked(ctx, keyName); err != nil {
		s.log.Error("failed to notify key revoked", "error", err)
	}

	return types.Key{
		ID:        key.ID,
		CoreID:    key.CoreID.String(),
		ProjectID: key.ProjectID,
		CreatedAt: key.CreatedAt,
		RevokedAt: key.RevokedAt.Time,
		Revision:  key.Revision,
	}, nil
}

func (s *KeysStorage) notifyKeyRevoked(ctx context.Context, name types.KeyName) error {
	// Compose key revoked event.
	e := authzunsafeeventsv1alpha.KeyRevoked{
		Name: string(name),
	}

	// Marshal the message to the protobuf format.
	md, err := proto.Marshal(&e)
	if err != nil {
		return err
	}

	// Send the message to the topic asynchronously.
	msg := pubsub.Message{Body: md}
	if err = s.keyRevoked().Send(ctx, &msg); err != nil {
		return err
	}
	return nil
}
