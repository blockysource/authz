package adminhandlerv1alpha

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/pallinder/go-randomdata"
	"go.einride.tech/aip/pagination"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blockysource/authz/internal/errdet"
	admindriver2 "github.com/blockysource/authz/persistence/driver"
	"github.com/blockysource/authz/persistence/types"
	"github.com/blockysource/go-genproto/blocky/api"

	"github.com/blockysource/authz/types/signalg"
	"github.com/blockysource/blockysql"
	"github.com/blockysource/blockysql/bserr"
	authzadminv1alpha "github.com/blockysource/go-genproto/blocky/authz/admin/v1alpha"
	"github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"
)

var _ authzadminv1alpha.KeysAdminServiceServer = (*KeysHandler)(nil)

// KeysHandler is the handler for the keys admin service.
type KeysHandler struct {
	authzadminv1alpha.UnimplementedKeysAdminServiceServer `wire:"-"`

	db *blockysql.DB
	ks admindriver2.KeysStorage
	cs admindriver2.ConfigStorage
}

// ListKeys is a method to list all keys.
// If the page size is not provided, it will be defaulted to 50.
func (h *KeysHandler) ListKeys(ctx context.Context, req *authzadminv1alpha.ListKeysRequest) (*authzadminv1alpha.ListKeysResponse, error) {
	if req == nil {
		return nil, status.Error(codes.Internal, "nil request provided")
	}

	proto.GetExtension(authzadminv1alpha.File_blocky_authz_admin_v1alpha_admin_keys_proto.Services().ByName("KeysAdmin").Methods().
		ByName("ListKeys").Options(), api.E_QueryParams).(*api.QueryParameters)


	// By default, return 50 keys.
	if req.PageSize < 0 {
		req.PageSize = 50
	}

	// Do not allow queries for more than 300 keys.
	if req.PageSize > 300 {
		req.PageSize = 300
	}

	token, err := pagination.ParsePageToken(req)
	if err != nil {
		return nil, errdet.BadRequest("invalid page token", &errdetails.BadRequest_FieldViolation{
			Field:       "page_token",
			Description: "invalid page token",
		})
	}

	lk := typesdb.ListKeysQuery{
		Offset:   token.Offset,
		PageSize: req.PageSize,
	}

	var result typesdb.ListKeysResult
	err = h.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		result.Keys, err = h.ks.ListKeys(ctx, tx, lk)
		if err != nil {
			return err
		}

		result.TotalSize, err = h.ks.CountKeys(ctx, tx)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		switch h.db.ErrorCode(err) {
		case bserr.Timeout:
			// The operation timed out.
			return nil, status.Error(codes.DeadlineExceeded, "operation timed out")
		default:
			return nil, status.Error(codes.Internal, "unexpected database error occurred")
		}
	}

	out := make([]*authzadminv1alpha.Key, 0, len(result.Keys))
	for _, key := range result.Keys {
		rk := authzadminv1alpha.Key{
			Name:           fmt.Sprintf("keys/%s", key.KeyID),
			KeyId:          key.KeyID,
			DisplayName:    key.DisplayName,
			CreateTime:     timestamppb.New(key.CreatedAt),
			Active:         key.Active,
			RotationPeriod: durationpb.New(key.RotationPeriod),
			Priority:       key.Priority,
			Versions:       key.Versions,
		}

		// Copy the algorithms.
		rk.Algorithms = make([]signalgpb.SigningAlgorithm, len(key.Algorithms))
		for i, alg := range key.Algorithms {
			rk.Algorithms[i] = signalgpb.SigningAlgorithm(alg)
		}

		// Set the last rotated time if it is valid.
		if key.LastRotatedAt.Valid {
			rk.LastRotatedTime = timestamppb.New(key.LastRotatedAt.Time)
		}

		// Set the revoked time if it is valid.
		if key.RevokedAt.Valid {
			rk.RevokeTime = timestamppb.New(key.RevokedAt.Time)
		}

		out = append(out, &rk)
	}

	// If there are more keys, set the next page token.
	var nextPageToken string
	if len(out) == int(req.PageSize) {
		nextPageToken = token.Next(req).String()
	}
	return &authzadminv1alpha.ListKeysResponse{
		Keys:          out,
		NextPageToken: nextPageToken,
		TotalSize:     result.TotalSize,
	}, nil
}

// keyRegexp is a regular expression to validate the key identifier format. ([a-z][0-9]-/.)
var keyRegexp = regexp.MustCompile(`^[a-z0-9-]+$`)

// CreateKey is an implementation of the CreateKey RPC.
// It will create a new key with the provided parameters.
// If the key identifier is not provided or is empty, it will be auto-generated.
// If the key name is not provided or is empty, it will be auto-generated.
func (h *KeysHandler) CreateKey(ctx context.Context, req *authzadminv1alpha.CreateKeyRequest) (*authzadminv1alpha.Key, error) {
	if req.Key == nil {
		return nil, errdet.BadRequest("invalid input arguments", &errdetails.BadRequest_FieldViolation{
			Field:       "key",
			Description: "key cannot be nil",
		})
	}

	// Verify the key identifier is valid, if undefined the key identifier will be auto-generated from the storage layer.
	if req.KeyId != "" {
		if !keyRegexp.MatchString(req.KeyId) {
			return nil, errdet.BadRequest("invalid input arguments", &errdetails.BadRequest_FieldViolation{
				Field:       "key_id",
				Description: "key identifier must be in the format of [a-z0-9-]+",
			})
		}
	}

	// Check if the key identifier is provided.
	ckQuery := typesdb.CreateKey{
		KeyID:       req.KeyId,
		DisplayName: req.Key.DisplayName,
		Priority:    req.Key.Priority,
		Active:      req.Key.Active,
	}

	// Verify signing algorithms, which cannot be empty, cannot contain duplicates and cannot contain unsupported algorithms.
	if len(req.Key.Algorithms) == 0 {
		return nil, errdet.BadRequest("invalid input arguments", &errdetails.BadRequest_FieldViolation{
			Field:       "algorithms",
			Description: "signing algorithms cannot be empty",
		})
	}

	// Check if the signing algorithms contain duplicates and unsupported algorithms.
	dups := map[signalgpb.SigningAlgorithm]struct{}{}
	for _, alg := range req.Key.Algorithms {
		if alg == signalgpb.SigningAlgorithm_SIGNING_ALGORITHM_UNSPECIFIED {
			return nil, errdet.BadRequest("invalid input arguments", &errdetails.BadRequest_FieldViolation{
				Field:       "algorithms",
				Description: "unspecified signing algorithm is not supported",
			})
		}

		if _, ok := dups[alg]; ok {
			return nil, errdet.BadRequest("invalid input arguments", &errdetails.BadRequest_FieldViolation{
				Field:       "algorithms",
				Description: fmt.Sprintf("duplicate signing algorithm %q", alg),
			})
		}
		dups[alg] = struct{}{}
	}

	ckQuery.SigningAlgorithms = make([]signalg.SigningAlgorithm, len(req.Key.Algorithms))
	for i, alg := range req.Key.Algorithms {
		ckQuery.SigningAlgorithms[i] = signalg.SigningAlgorithm(alg)
	}

	// Check if the key name is provided.
	if ckQuery.DisplayName == "" {
		var sb strings.Builder
		sb.WriteString(randomdata.SillyName())
		for i, alg := range ckQuery.SigningAlgorithms {
			if i < len(ckQuery.SigningAlgorithms) {
				sb.WriteRune('-')
			}
			sb.WriteString(alg.String())
		}
		ckQuery.DisplayName = sb.String()
	}

	if req.Key.RotationPeriod != nil {
		ckQuery.RotationPeriod = req.Key.RotationPeriod.AsDuration()
	}

	var dbKey typesdb.Key
	err := h.db.RunInTransaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		// If the rotation period is not provided, use the default value from the service configuration.
		if req.Key.RotationPeriod == nil {
			cfg, err := h.cs.GetServiceConfig(ctx, tx)
			if err != nil {
				return err
			}
			ckQuery.RotationPeriod = cfg.KeyRotationPeriod
		}

		// If the key identifier is not provided, get the next key identifier.
		if ckQuery.KeyID == "" {
			// Get the next key identifier.
			keyID, err := h.ks.GetNextKeyTableID(ctx, tx)
			if err != nil {
				return err
			}

			// Convert the key identifier to the key table identifier.
			ckQuery.TableID = keyID
			ckQuery.KeyID = strconv.FormatInt(int64(keyID), 10)
		}

		var err error
		dbKey, err = h.ks.CreateKey(ctx, tx, ckQuery)
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		switch h.db.ErrorCode(err) {
		case bserr.Timeout:
			// The operation timed out.
			return nil, status.Error(codes.DeadlineExceeded, "operation timed out")
		case bserr.NotFound:
			// The service configuration is not found.
			s := status.New(codes.Internal, "service configuration undefined")
			ds, err := s.WithDetails(&errdetails.PreconditionFailure{
				Violations: []*errdetails.PreconditionFailure_Violation{
					{
						Type:        "serviceconfig",
						Subject:     "service configuration",
						Description: "the service configuration is undefined",
					},
				},
			},
			)
			if err != nil {
				return nil, s.Err()
			}
			return nil, ds.Err()
		case bserr.UniqueViolation:
			// The key with the same key identifier already exists.
			return nil, errdet.AlreadyExists("key with the same key identifier already exists", &errdetails.BadRequest_FieldViolation{
				Field:       "key_id",
				Description: fmt.Sprintf("key with the same key identifier %q already exists", ckQuery.KeyID),
			})
		default:
			return nil, status.Error(codes.Internal, "unexpected database error occurred")
		}
	}

	// This will increase once the first key version is created, this should be done asynchronously.
	// But we're returning the key version as 1, assuming that the key version is eventually created successfully.
	versionsNo := int32(1)
	out := &authzadminv1alpha.Key{
		Name:        fmt.Sprintf("key/%s", dbKey.KeyID),
		KeyId:       dbKey.KeyID,
		Algorithms:  req.Key.Algorithms,
		DisplayName: dbKey.DisplayName,
		CreateTime:  timestamppb.New(dbKey.CreatedAt),
		Priority:    dbKey.Priority,
		Versions:    versionsNo,
	}

	return out, nil
}

func (h *KeysHandler) ActivateKey(ctx context.Context, req *authzadminv1alpha.ActivateKeyRequest) (*authzadminv1alpha.ActivateKeyResponse, error) {
	panic("implement me")
}

func (h *KeysHandler) RevokeKeyVersion(ctx context.Context, req *authzadminv1alpha.RevokeKeyVersionRequest) (*authzadminv1alpha.RevokeKeyVersionResponse, error) {
	// TODO implement me
	panic("implement me")
}

func (h *KeysHandler) ListKeyVersions(ctx context.Context, req *authzadminv1alpha.ListKeyVersionsRequest) (*authzadminv1alpha.ListKeyVersionsResponse, error) {
	// TODO implement me
	panic("implement me")
}
