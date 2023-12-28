// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package adminv1alpha

import (
	"context"
	"github.com/blockysource/authz/logic/keys"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blockysource/authz/types/algorithm"
	"github.com/blockysource/blocky-aip/expr"
	"github.com/blockysource/blocky-aip/fieldmask"
	"github.com/blockysource/blocky-aip/ordering"
	"github.com/blockysource/blocky-aip/pagination"
	blockyannotations "github.com/blockysource/go-genproto/blocky/api/annotations"
	authzadminv1alpha "github.com/blockysource/go-genproto/blocky/authz/admin/v1alpha"
	"github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"

	"github.com/blockysource/authz/persistence/admindb"
	"github.com/blockysource/authz/types"
)

var _ authzadminv1alpha.KeyAdminServiceServer = (*KeysServiceHandler)(nil)

// KeysServiceHandler is a keys admin handler.
type KeysServiceHandler struct {
	authzadminv1alpha.UnimplementedKeyAdminServiceServer `wire:"-"`

	listKeyCores, listKeys, listKeyCoreKeys struct {
		orderBy       *expr.OrderByExpr
		pageSize      int64
		maxPageSize   int32
		maxComplexity int64
	} `wire:"-"`

	updateKey struct {
		fmp fieldmask.Parser
	} `wire:"-"`

	storage *admindb.KeysStorage
	keyGen keys.SigningKeyGenerator

	log   *slog.Logger
}

func (h *KeysServiceHandler) init() {
	// Initialize the key handler parameters from the file descriptor.
	svc := authzadminv1alpha.File_blocky_authz_admin_v1alpha_key_admin_proto.Services().
		ByName("KeyAdminService")
	if svc == nil {
		panic("key admin service not found")
	}

	h.initListKeyCoresMethod(svc)
	h.initListKeysMethod(svc)
	h.initListKeyCoreKeysMethod(svc)
	h.initUpdateKeyMethod()
}

func (h *KeysServiceHandler) initListKeyCoresMethod(svc protoreflect.ServiceDescriptor) {
	// Get the ListKeys method.
	lkm := svc.Methods().ByName("ListKeyCores")
	if lkm == nil {
		panic("list key revisions method not found")
	}

	qp, ok := proto.GetExtension(lkm.Options(), blockyannotations.E_QueryParams).(*blockyannotations.QueryParameters)
	if !ok {
		panic("query parameters not found")
	}

	keyDesc := new(authzadminv1alpha.Key).ProtoReflect()
	op, err := ordering.NewParser(keyDesc.Descriptor())
	if err != nil {
		panic(err)
	}

	oe, err := op.Parse(qp.OrderBy)
	if err != nil {
		panic(err)
	}

	h.listKeyCores.orderBy = oe

	if qp.Pagination != nil {
		h.listKeyCores.pageSize = qp.Pagination.DefaultSize
		h.listKeyCores.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listKeyCores.maxComplexity = qp.MaxComplexity
}

func (h *KeysServiceHandler) initListKeysMethod(svc protoreflect.ServiceDescriptor) {
	lkm := svc.Methods().ByName("ListKeys")
	if lkm == nil {
		panic("list keys method not found")
	}

	qp, ok := proto.GetExtension(lkm.Options(), blockyannotations.E_QueryParams).(*blockyannotations.QueryParameters)
	if !ok {
		panic("query parameters not found")
	}

	keyDesc := new(authzadminv1alpha.Key).ProtoReflect()
	op, err := ordering.NewParser(keyDesc.Descriptor())
	if err != nil {
		panic(err)
	}

	oe, err := op.Parse(qp.OrderBy)
	if err != nil {
		panic(err)
	}

	h.listKeys.orderBy = oe

	if qp.Pagination != nil {
		h.listKeys.pageSize = qp.Pagination.DefaultSize
		h.listKeys.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listKeys.maxComplexity = qp.MaxComplexity
}

func (h *KeysServiceHandler) initListKeyCoreKeysMethod(svc protoreflect.ServiceDescriptor) {
	lkm := svc.Methods().ByName("ListKeyCoreKeys")
	if lkm == nil {
		panic("list keys method not found")
	}

	qp, ok := proto.GetExtension(lkm.Options(), blockyannotations.E_QueryParams).(*blockyannotations.QueryParameters)
	if !ok {
		panic("query parameters not found")
	}

	keyDesc := new(authzadminv1alpha.Key).ProtoReflect()
	op, err := ordering.NewParser(keyDesc.Descriptor())
	if err != nil {
		panic(err)
	}

	oe, err := op.Parse(qp.OrderBy)
	if err != nil {
		panic(err)
	}

	h.listKeyCoreKeys.orderBy = oe

	if qp.Pagination != nil {
		h.listKeyCoreKeys.pageSize = qp.Pagination.DefaultSize
		h.listKeyCoreKeys.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listKeyCoreKeys.maxComplexity = qp.MaxComplexity
}

func (h *KeysServiceHandler) initUpdateKeyMethod() {
	var fmp fieldmask.Parser
	err := fmp.Reset(new(authzadminv1alpha.Key), fieldmask.IgnoreNonUpdatableOption)
	if err != nil {
		panic(err)
	}
	h.updateKey.fmp = fmp
}

// CreateKeyCore creates a new key.
func (h *KeysServiceHandler) CreateKeyCore(ctx context.Context, req *authzadminv1alpha.CreateKeyCoreRequest) (*authzadminv1alpha.KeyCore, error) {
	if err := h.validateCreateKeyCore(ctx, req); err != nil {
		return nil, err
	}

	// Extract project identifier.
	pn := types.ProjectName(req.Parent)
	pID := pn.Project()

	// Create key query.
	cq := admindb.CreateKeyCoreQuery{
		ProjectID:   pID,
		DisplayName: req.KeyCore.DisplayName,
		Algorithm:   algorithm.SigningAlgorithm(req.KeyCore.Algorithm),
	}
	if req.KeyCore.RotationInterval != nil {
		cq.RotationInterval = req.KeyCore.RotationInterval.AsDuration()
	}

	// Create the key.
	keyCore, err := h.storage.CreateKeyCore(ctx, cq)
	if err != nil {
		return nil, err
	}

	// Compose key name.
	kn := types.ComposeKeyCoreName(pID, keyCore.ID)

	var rp *durationpb.Duration
	if keyCore.RotationInterval != 0 {
		rp = durationpb.New(keyCore.RotationInterval)
	}
	return &authzadminv1alpha.KeyCore{
		Name:             kn.String(),
		Uid:              keyCore.ID,
		Algorithm:        signalgpb.SigningAlgorithm(keyCore.Algorithm),
		DisplayName:      keyCore.DisplayName,
		CreateTime:       timestamppb.New(keyCore.CreatedAt),
		UpdateTime:       timestamppb.New(keyCore.UpdatedAt),
		LastRotatedTime:  nil,
		RotationInterval: rp,
		Priority:         int32(keyCore.Priority),
		DerivedKeysCount: 0,
	}, nil
}

func (h *KeysServiceHandler) validateCreateKeyCore(ctx context.Context, req *authzadminv1alpha.CreateKeyCoreRequest) error {
	var br errdetails.BadRequest
	if req.KeyCore == nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "key_core",
			Description: "field is required",
		})
	}

	if req.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "field cannot be empty",
		})
	} else {
		pn := types.ProjectName(req.Parent)
		if err := pn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "parent",
				Description: err.Error(),
			})
		}
	}

	k := req.KeyCore
	if k == nil {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return s.Err()
		}
		return sb.Err()
	}

	if k.Name != "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "key_core.name",
			Description: "key_core.name is an identifier and cannot be set",
		})
	}

	if k.Uid != "" {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key_core.uid")
	}

	if k.CreateTime != nil {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key_core.create_time")
	}

	if k.UpdateTime != nil {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key_core.update_time")
	}

	if k.LastRotatedTime != nil {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key_core.last_rotated_time")
	}

	if k.DerivedKeysCount != 0 {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key_core.derived_keys_count")
	}

	if len(br.FieldViolations) > 0 {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return s.Err()
		}
		return sb.Err()
	}

	return nil
}

// GetKeyCore implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) GetKeyCore(ctx context.Context, req *authzadminv1alpha.GetKeyCoreRequest) (*authzadminv1alpha.KeyCore, error) {
	if err := h.validateGetKeyCore(ctx, req); err != nil {
		return nil, err
	}

	kn := types.KeyCoreName(req.Name)

	pID := kn.Project()
	keyID := kn.KeyCore()

	key, err := h.storage.GetKeyCore(ctx, pID, keyID)
	if err != nil {
		return nil, err
	}

	var rp *durationpb.Duration
	if key.RotationInterval != 0 {
		rp = durationpb.New(key.RotationInterval)
	}
	var lr *timestamppb.Timestamp
	if !key.LastRotatedAt.IsZero() {
		lr = timestamppb.New(key.LastRotatedAt)
	}
	return &authzadminv1alpha.KeyCore{
		Name:             kn.String(),
		Uid:              key.ID,
		Algorithm:        signalgpb.SigningAlgorithm(key.Algorithm),
		DisplayName:      key.DisplayName,
		CreateTime:       timestamppb.New(key.CreatedAt),
		UpdateTime:       timestamppb.New(key.UpdatedAt),
		LastRotatedTime:  lr,
		RotationInterval: rp,
		Priority:         int32(key.Priority),
		DerivedKeysCount: int32(key.DerivedKeysCount),
	}, nil
}

func (h *KeysServiceHandler) validateGetKeyCore(ctx context.Context, req *authzadminv1alpha.GetKeyCoreRequest) error {
	var br errdetails.BadRequest
	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "name is required",
		})
	} else {
		kn := types.KeyCoreName(req.Name)
		if err := kn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "name",
				Description: err.Error(),
			})
		}
	}

	if len(br.FieldViolations) > 0 {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return s.Err()
		}
		return sb.Err()
	}

	return nil
}

// nextPageToken is the next page token. It is used to paginate the results.
type nextPageToken struct {
	PageSize int32
	Skip     int32
}

// ListKeyCores implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) ListKeyCores(ctx context.Context, req *authzadminv1alpha.ListKeyCoresRequest) (*authzadminv1alpha.ListKeyCoresResponse, error) {
	npt, err := h.validateListKeyCores(ctx, req)
	if err != nil {
		return nil, err
	}

	pn := types.ProjectName(req.Parent)
	pID := pn.Project()

	q := admindb.ListKeyCoresQuery{
		ProjectID: pID,
		PageSize:  int(req.PageSize),
		OrderBy:   h.listKeyCores.orderBy,
	}

	if req.PageToken != "" {
		q.PageSize = int(npt.PageSize)
		q.Skip = int(npt.Skip)
	}

	if q.PageSize > int(h.listKeyCores.maxPageSize) {
		q.PageSize = int(h.listKeyCores.maxPageSize)
	}
	if q.PageSize == 0 {
		q.PageSize = int(h.listKeyCores.pageSize)
	}

	res, err := h.storage.ListKeyCores(ctx, q)
	if err != nil {
		return nil, err
	}

	// Check if the next page token is required.
	var nptOut string
	if len(res.KeyCores) == q.PageSize && res.Total > int64(q.PageSize)+int64(q.Skip) {
		nptOut, err = pagination.TokenizeStruct(nextPageToken{
			PageSize: int32(q.PageSize),
			Skip:     int32(q.Skip) + int32(q.PageSize),
		})
		if err != nil {
			return nil, err
		}
	}

	// Compose the response.
	out := &authzadminv1alpha.ListKeyCoresResponse{
		KeyCores:      make([]*authzadminv1alpha.KeyCore, len(res.KeyCores)),
		NextPageToken: nptOut,
	}

	for i, key := range res.KeyCores {
		var rp *durationpb.Duration
		if key.RotationInterval != 0 {
			rp = durationpb.New(key.RotationInterval)
		}
		var lr *timestamppb.Timestamp
		if !key.LastRotatedAt.IsZero() {
			lr = timestamppb.New(key.LastRotatedAt)
		}
		out.KeyCores[i] = &authzadminv1alpha.KeyCore{
			Name:             types.ComposeKeyCoreName(pID, key.ID).String(),
			Uid:              key.ID,
			Algorithm:        signalgpb.SigningAlgorithm(key.Algorithm),
			DisplayName:      key.DisplayName,
			CreateTime:       timestamppb.New(key.CreatedAt),
			UpdateTime:       timestamppb.New(key.UpdatedAt),
			LastRotatedTime:  lr,
			RotationInterval: rp,
			Priority:         int32(key.Priority),
			DerivedKeysCount: int32(key.DerivedKeysCount),
		}
	}

	return out, nil
}

func (h *KeysServiceHandler) validateListKeyCores(ctx context.Context, req *authzadminv1alpha.ListKeyCoresRequest) (nextPageToken, error) {
	var br errdetails.BadRequest
	if req.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "parent is required",
		})
	} else {
		pn := types.ProjectName(req.Parent)
		if err := pn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "parent",
				Description: err.Error(),
			})
		}
	}

	if req.PageSize < 0 {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "page_size",
			Description: "page_size must be greater than or equal to 0",
		})
	}

	npt, err := pagination.DecodeToken[nextPageToken](req.PageToken)
	if err != nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "page_token",
			Description: err.Error(),
		})
	}

	if len(br.FieldViolations) > 0 {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return npt, s.Err()
		}
		return npt, sb.Err()
	}

	return npt, nil
}

// ListKeyCoreKeys implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) ListKeyCoreKeys(ctx context.Context, req *authzadminv1alpha.ListKeyCoreKeysRequest) (*authzadminv1alpha.ListKeyCoreKeysResponse, error) {
	npt, err := h.validateListKeyCoreKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	kn := types.KeyCoreName(req.Parent)
	pID := kn.Project()
	core := kn.KeyCore()

	q := admindb.ListKeysQuery{
		ProjectID: pID,
		CoreID:    core,
		PageSize:  int(req.PageSize),
		OrderBy:   h.listKeyCoreKeys.orderBy,
	}

	if req.PageToken != "" {
		q.PageSize = int(npt.PageSize)
		q.Skip = int(npt.Skip)
	}

	if q.PageSize > int(h.listKeyCoreKeys.maxPageSize) {
		q.PageSize = int(h.listKeyCoreKeys.maxPageSize)
	}

	if q.PageSize == 0 {
		q.PageSize = int(h.listKeyCoreKeys.pageSize)
	}

	res, err := h.storage.ListKeys(ctx, q)
	if err != nil {
		return nil, err
	}

	// Check if the next page token is required.
	var nptOut string
	if len(res.Keys) == q.PageSize && res.Total > int64(q.PageSize)+int64(q.Skip) {
		nptOut, err = pagination.TokenizeStruct(nextPageToken{
			PageSize: int32(q.PageSize),
			Skip:     int32(q.Skip) + int32(q.PageSize),
		})
		if err != nil {
			return nil, err
		}
	}

	// Compose the response.
	out := &authzadminv1alpha.ListKeyCoreKeysResponse{
		Keys:          make([]*authzadminv1alpha.Key, len(res.Keys)),
		NextPageToken: nptOut,
	}

	for i, key := range res.Keys {
		var rt *timestamppb.Timestamp
		if !key.RevokedAt.IsZero() {
			rt = timestamppb.New(key.RevokedAt)
		}
		keyName := types.ComposeKeyName(pID, key.ID)
		coreName := types.ComposeKeyCoreName(pID, key.CoreID)
		out.Keys[i] = &authzadminv1alpha.Key{
			Name:           keyName.String(),
			KeyId:          key.ID,
			CreateTime:     timestamppb.New(key.CreatedAt),
			RevisionNumber: int32(key.Revision),
			RevokeTime:     rt,
			Core:           coreName.String(),
		}
	}

	return out, nil
}

func (h *KeysServiceHandler) validateListKeyCoreKeys(ctx context.Context, req *authzadminv1alpha.ListKeyCoreKeysRequest) (nextPageToken, error) {
	var br errdetails.BadRequest
	if req.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "parent is required",
		})
	} else {
		pn := types.KeyCoreName(req.Parent)
		if err := pn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "parent",
				Description: err.Error(),
			})
		}
	}

	if req.PageSize < 0 {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "page_size",
			Description: "page_size must be greater than or equal to 0",
		})
	}

	npt, err := pagination.DecodeToken[nextPageToken](req.PageToken)
	if err != nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "page_token",
			Description: "malformed page token",
		})
	}

	if len(br.FieldViolations) > 0 {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "violations", br.FieldViolations)
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return npt, s.Err()
		}
		return npt, sb.Err()
	}

	return npt, nil
}

// UpdateKeyCore implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) UpdateKeyCore(ctx context.Context, req *authzadminv1alpha.UpdateKeyCoreRequest) (*authzadminv1alpha.KeyCore, error) {
	if err := h.validateUpdateKeyCore(ctx, req); err != nil {
		return nil, err
	}

	x, err := h.updateKey.fmp.ParseUpdateExpr(req.KeyCore, req.UpdateMask)
	if err != nil {
		return nil, err
	}

	defer x.Free()

	kn := types.KeyCoreName(req.Name)

	key, err := h.storage.UpdateKeyCore(ctx, admindb.UpdateKeyCoreQuery{
		ProjectID: kn.Project(),
		KeyCoreID: kn.KeyCore(),
		Expr:      x,
	})
	if err != nil {
		return nil, err
	}

	// Recompose key name, as the input could have an alias.
	kn = types.ComposeKeyCoreName(key.ProjectID, key.ID)

	var ri *durationpb.Duration
	if key.RotationInterval != 0 {
		ri = durationpb.New(key.RotationInterval)
	}

	var lr *timestamppb.Timestamp
	if !key.LastRotatedAt.IsZero() {
		lr = timestamppb.New(key.LastRotatedAt)
	}

	return &authzadminv1alpha.KeyCore{
		Name:             kn.String(),
		Uid:              key.ID,
		Algorithm:        signalgpb.SigningAlgorithm(key.Algorithm),
		DisplayName:      key.DisplayName,
		CreateTime:       timestamppb.New(key.CreatedAt),
		UpdateTime:       timestamppb.New(key.UpdatedAt),
		LastRotatedTime:  lr,
		RotationInterval: ri,
		Priority:         int32(key.Priority),
		DerivedKeysCount: int32(key.DerivedKeysCount),
	}, nil
}

func (h *KeysServiceHandler) validateUpdateKeyCore(ctx context.Context, req *authzadminv1alpha.UpdateKeyCoreRequest) error {
	var br errdetails.BadRequest
	if req.KeyCore == nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "key_core",
			Description: "field is required",
		})
	}

	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "field is required",
		})
	} else {
		kn := types.KeyCoreName(req.Name)
		if err := kn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "name",
				Description: err.Error(),
			})
		}
	}

	if req.UpdateMask == nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "update_mask",
			Description: "field is required",
		})
	}

	k := req.KeyCore
	if k == nil {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return s.Err()
		}
		return sb.Err()
	}

	return nil
}

// RotateKey implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) RotateKey(ctx context.Context, req *authzadminv1alpha.RotateKeyRequest) (*authzadminv1alpha.Key, error) {
	if err := h.validateRotateKey(ctx, req); err != nil {
		return nil, err
	}

	kn := types.KeyCoreName(req.Parent)

	key, err := h.storage.RotateKey(ctx, admindb.RotateKeyQuery{
		ProjectID:         kn.Project(),
		KeyCoreIdentifier: kn.KeyCore(),
		KeyGenerator: h.keyGen,
	})
	if err != nil {
		return nil, err
	}

	// Compose key revision name.
	keyName := types.ComposeKeyName(kn.Project(), key.ID)
	coreName := types.ComposeKeyCoreName(kn.Project(), key.CoreID)

	return &authzadminv1alpha.Key{
		Name:           keyName.String(),
		KeyId:          key.ID,
		CreateTime:     timestamppb.New(key.CreatedAt),
		RevisionNumber: int32(key.Revision),
		Core:           coreName.String(),
	}, nil
}

func (h *KeysServiceHandler) validateRotateKey(ctx context.Context, req *authzadminv1alpha.RotateKeyRequest) error {
	var br errdetails.BadRequest
	if req.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "field is required",
		})
	} else {
		pn := types.KeyCoreName(req.Parent)
		if err := pn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "parent",
				Description: err.Error(),
			})
		}
	}

	// Nothing to verify within revision.
	if len(br.FieldViolations) > 0 {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return s.Err()
		}
		return sb.Err()
	}

	return nil
}

// GetKey implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) GetKey(ctx context.Context, req *authzadminv1alpha.GetKeyRequest) (*authzadminv1alpha.Key, error) {
	if err := h.validateGetKey(req); err != nil {
		return nil, err
	}

	keyName := types.KeyName(req.Name)

	key, err := h.storage.GetKey(ctx, admindb.GetKeyQuery{
		ProjectID: keyName.Project(),
		KeyID:     keyName.Key(),
	})
	if err != nil {
		return nil, err
	}

	keyName = types.ComposeKeyName(key.ProjectID, key.CoreID)
	var rt *timestamppb.Timestamp
	if !key.RevokedAt.IsZero() {
		rt = timestamppb.New(key.RevokedAt)
	}

	coreName := types.ComposeKeyCoreName(key.ProjectID, key.CoreID)

	return &authzadminv1alpha.Key{
		Name:           keyName.String(),
		KeyId:          key.ID,
		CreateTime:     timestamppb.New(key.CreatedAt),
		RevisionNumber: int32(key.Revision),
		RevokeTime:     rt,
		Core:           coreName.String(),
	}, nil
}

func (h *KeysServiceHandler) validateGetKey(req *authzadminv1alpha.GetKeyRequest) error {
	var br errdetails.BadRequest
	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "field is required",
		})
	} else {
		krn := types.KeyName(req.Name)
		if err := krn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "name",
				Description: err.Error(),
			})
		}
	}

	if len(br.FieldViolations) > 0 {
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return s.Err()
		}
		return sb.Err()
	}
	return nil
}

// ListKeys implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) ListKeys(ctx context.Context, req *authzadminv1alpha.ListKeysRequest) (*authzadminv1alpha.ListKeysResponse, error) {
	npt, err := h.validateListKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	project := types.ProjectName(req.Parent)

	q := admindb.ListKeysQuery{
		ProjectID: project.Project(),
		PageSize:  int(req.PageSize),
	}
	if req.PageToken != "" {
		q.PageSize = int(npt.PageSize)
		q.Skip = int(npt.Skip)
	} else if q.PageSize == 0 {
		q.PageSize = int(h.listKeys.pageSize)
	}

	q.OrderBy = h.listKeys.orderBy

	res, err := h.storage.ListKeys(ctx, q)
	if err != nil {
		return nil, err
	}

	// Check if the next page token is required.
	var nptOut string
	if len(res.Keys) == q.PageSize && res.Total > int64(q.PageSize)+int64(q.Skip) {
		nptOut, err = pagination.TokenizeStruct(nextPageToken{
			PageSize: int32(q.PageSize),
			Skip:     int32(q.Skip) + int32(q.PageSize),
		})
		if err != nil {
			h.log.ErrorContext(ctx, "failed to tokenize next page token", "error", err)
		}
	}

	out := authzadminv1alpha.ListKeysResponse{NextPageToken: nptOut}
	if len(res.Keys) > 0 {
		out.Keys = make([]*authzadminv1alpha.Key, len(res.Keys))

		var coreName types.KeyCoreName
		for i, key := range res.Keys {
			var rt *timestamppb.Timestamp
			if !key.RevokedAt.IsZero() {
				rt = timestamppb.New(key.RevokedAt)
			}

			keyName := types.ComposeKeyName(key.ProjectID, key.CoreID)
			if len(coreName) == 0 {
				coreName = types.ComposeKeyCoreName(key.ProjectID, key.CoreID)
			}

			out.Keys[i] = &authzadminv1alpha.Key{
				Name:           keyName.String(),
				KeyId:          key.ID,
				CreateTime:     timestamppb.New(key.CreatedAt),
				RevisionNumber: int32(key.Revision),
				RevokeTime:     rt,
				Core:           coreName.String(),
			}
		}
	}

	return &out, nil
}

func (h *KeysServiceHandler) validateListKeys(ctx context.Context, req *authzadminv1alpha.ListKeysRequest) (nextPageToken, error) {
	var br errdetails.BadRequest
	if req.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "field is required",
		})
	} else {
		pn := types.ProjectName(req.Parent)
		if err := pn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "parent",
				Description: err.Error(),
			})
		}
	}

	if req.PageSize < 0 {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "page_size",
			Description: "page_size must be greater than or equal to 0",
		})
	}

	var npt nextPageToken
	if req.PageToken != "" {
		var err error
		npt, err = pagination.DecodeToken[nextPageToken](req.PageToken)
		if err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "page_token",
				Description: "malformed page token",
			})
		}
	}

	if len(br.FieldViolations) > 0 {
		h.log.DebugContext(ctx, "invalid input", "violations", br.FieldViolations)
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return nextPageToken{}, s.Err()
		}
		return nextPageToken{}, sb.Err()
	}

	return npt, nil
}

// RevokeKey implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysServiceHandler) RevokeKey(ctx context.Context, req *authzadminv1alpha.RevokeKeyRequest) (*authzadminv1alpha.Key, error) {
	if err := h.validateRevokeKey(ctx, req); err != nil {
		return nil, err
	}

	keyName := types.KeyName(req.Name)
	key, err := h.storage.RevokeKey(ctx, admindb.RevokeKeyQuery{
		ProjectID: keyName.Project(),
		KeyID:     keyName.Key(),
	})
	if err != nil {
		return nil, err
	}

	keyName = types.ComposeKeyName(key.ProjectID, key.ID)
	coreName := types.ComposeKeyCoreName(key.ProjectID, key.CoreID)
	return &authzadminv1alpha.Key{
		Name:           keyName.String(),
		KeyId:          key.ID,
		CreateTime:     timestamppb.New(key.CreatedAt),
		RevisionNumber: int32(key.Revision),
		RevokeTime:     timestamppb.New(key.RevokedAt),
		Core:           coreName.String(),
	}, nil
}

func (h *KeysServiceHandler) validateRevokeKey(ctx context.Context, req *authzadminv1alpha.RevokeKeyRequest) error {
	var br errdetails.BadRequest
	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "field is required",
		})
	} else {
		krn := types.KeyName(req.Name)
		if err := krn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "name",
				Description: err.Error(),
			})
		}
	}

	if len(br.FieldViolations) > 0 {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "violations", protojson.Format(&br))
		}
		s := status.New(codes.InvalidArgument, "invalid input")
		sb, err := s.WithDetails(&br)
		if err != nil {
			return s.Err()
		}
		return sb.Err()
	}
	return nil
}
