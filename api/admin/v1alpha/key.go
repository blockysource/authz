// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package grpcadminv1alpha

import (
	"context"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blockysource/blocky-aip/expr"
	"github.com/blockysource/blocky-aip/fieldmask"
	"github.com/blockysource/blocky-aip/ordering"
	"github.com/blockysource/blocky-aip/pagination"
	blockyannotations "github.com/blockysource/go-genproto/blocky/api/annotations"
	authzadminv1alpha "github.com/blockysource/go-genproto/blocky/authz/admin/v1alpha"
	"github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"

	"github.com/blockysource/authz/persistence/admin"
	"github.com/blockysource/authz/types"
)

var _ authzadminv1alpha.KeyAdminServiceServer = (*KeysHandler)(nil)

// KeysHandler is a keys admin handler.
type KeysHandler struct {
	authzadminv1alpha.UnimplementedKeyAdminServiceServer `wire:"-"`

	listKeys, listKeyRevisions struct {
		orderBy       *expr.OrderByExpr
		pageSize      int64
		maxPageSize   int32
		maxComplexity int64
	} `wire:"-"`

	updateKey struct {
		fmp fieldmask.Parser
	} `wire:"-"`

	admin *admin.KeysStorage
	log   slog.Logger
}

func (h *KeysHandler) init() {
	// Initialize the key handler parameters from the file descriptor.
	svc := authzadminv1alpha.File_blocky_authz_admin_v1alpha_key_admin_proto.Services().
		ByName("KeyAdminService")
	if svc == nil {
		panic("key admin service not found")
	}

	h.initListKeysMethod(svc)
	h.initListKeyRevisionsMethod(svc)
	h.initUpdateKeyMethod()
}

func (h *KeysHandler) initListKeysMethod(svc protoreflect.ServiceDescriptor) {
	// Get the ListKeys method.
	lkm := svc.Methods().ByName("ListKeys")
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

	h.listKeys.orderBy = oe

	if qp.Pagination != nil {
		h.listKeys.pageSize = qp.Pagination.DefaultSize
		h.listKeys.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listKeys.maxComplexity = qp.MaxComplexity
}

func (h *KeysHandler) initListKeyRevisionsMethod(svc protoreflect.ServiceDescriptor) {
	lkm := svc.Methods().ByName("ListKeyRevisions")
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

	h.listKeyRevisions.orderBy = oe

	if qp.Pagination != nil {
		h.listKeyRevisions.pageSize = qp.Pagination.DefaultSize
		h.listKeyRevisions.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listKeyRevisions.maxComplexity = qp.MaxComplexity
}

func (h *KeysHandler) initUpdateKeyMethod() {
	var fmp fieldmask.Parser
	err := fmp.Reset(new(authzadminv1alpha.Key), fieldmask.IgnoreNonUpdatableOption)
	if err != nil {
		panic(err)
	}
	h.updateKey.fmp = fmp
}

// CreateKey creates a new key.
func (h *KeysHandler) CreateKey(ctx context.Context, req *authzadminv1alpha.CreateKeyRequest) (*authzadminv1alpha.Key, error) {
	if err := h.validateCreateKey(ctx, req); err != nil {
		return nil, err
	}

	// Extract project identifier.
	pn := types.ProjectName(req.Parent)
	pID := pn.Project()

	// Create key query.
	cq := admin.CreateKeyQuery{
		ProjectID:   pID,
		DisplayName: req.Key.DisplayName,
		Algorithm:   types.SigningAlgorithm(req.Key.Algorithm),
	}
	if req.Key.RotationPeriod != nil {
		cq.RotationPeriod = req.Key.RotationPeriod.AsDuration()
	}

	// Create the key.
	key, err := h.admin.CreateKey(ctx, cq)
	if err != nil {
		return nil, err
	}

	// Compose key name.
	kn := types.ComposeKeyName(pID, key.ID)

	var rp *durationpb.Duration
	if key.RotationPeriod != 0 {
		rp = durationpb.New(key.RotationPeriod)
	}
	return &authzadminv1alpha.Key{
		Name:            kn.String(),
		Uid:             key.ID,
		Algorithm:       signalgpb.SigningAlgorithm(key.Algorithm),
		DisplayName:     key.DisplayName,
		CreateTime:      timestamppb.New(key.CreatedAt),
		UpdateTime:      timestamppb.New(key.UpdatedAt),
		LastRotatedTime: nil,
		RotationPeriod:  rp,
		Priority:        int32(key.Priority),
		Revisions:       0,
	}, nil
}

func (h *KeysHandler) validateCreateKey(ctx context.Context, req *authzadminv1alpha.CreateKeyRequest) error {
	var br errdetails.BadRequest
	if req.Key == nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "key",
			Description: "key is required",
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

	k := req.Key
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
			Field:       "key.name",
			Description: "key.name is an identifier and cannot be set",
		})
	}

	if k.Uid != "" {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key.uid")
	}

	if k.CreateTime != nil {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key.create_time")
	}

	if k.UpdateTime != nil {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key.update_time")
	}

	if k.LastRotatedTime != nil {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key.last_rotated_time")
	}

	if k.Revisions != 0 {
		h.log.DebugContext(ctx, "is an output only field and cannot be set on creation", "field", "key.revisions")
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

// GetKey implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysHandler) GetKey(ctx context.Context, req *authzadminv1alpha.GetKeyRequest) (*authzadminv1alpha.Key, error) {
	if err := h.validateGetKey(ctx, req); err != nil {
		return nil, err
	}

	kn := types.KeyName(req.Name)

	pID := kn.Project()
	keyID := kn.Key()

	key, err := h.admin.GetKey(ctx, pID, keyID)
	if err != nil {
		return nil, err
	}

	var rp *durationpb.Duration
	if key.RotationPeriod != 0 {
		rp = durationpb.New(key.RotationPeriod)
	}
	var lr *timestamppb.Timestamp
	if !key.LastRotatedAt.IsZero() {
		lr = timestamppb.New(key.LastRotatedAt)
	}
	return &authzadminv1alpha.Key{
		Name:            kn.String(),
		Uid:             key.ID,
		Algorithm:       signalgpb.SigningAlgorithm(key.Algorithm),
		DisplayName:     key.DisplayName,
		CreateTime:      timestamppb.New(key.CreatedAt),
		UpdateTime:      timestamppb.New(key.UpdatedAt),
		LastRotatedTime: lr,
		RotationPeriod:  rp,
		Priority:        int32(key.Priority),
		Revisions:       int32(key.Revisions),
	}, nil
}

func (h *KeysHandler) validateGetKey(ctx context.Context, req *authzadminv1alpha.GetKeyRequest) error {
	var br errdetails.BadRequest
	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "name is required",
		})
	} else {
		kn := types.KeyName(req.Name)
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

// ListKeys implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysHandler) ListKeys(ctx context.Context, req *authzadminv1alpha.ListKeysRequest) (*authzadminv1alpha.ListKeysResponse, error) {
	npt, err := h.validateListKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	pn := types.ProjectName(req.Parent)
	pID := pn.Project()

	q := admin.ListKeysQuery{
		ProjectID: pID,
		PageSize:  int(req.PageSize),
		OrderBy:   h.listKeys.orderBy,
	}

	if req.PageToken != "" {
		q.PageSize = int(npt.PageSize)
		q.Skip = int(npt.Skip)
	}

	if q.PageSize > int(h.listKeys.maxPageSize) {
		q.PageSize = int(h.listKeys.maxPageSize)
	}
	if q.PageSize == 0 {
		q.PageSize = int(h.listKeys.pageSize)
	}

	res, err := h.admin.ListKeys(ctx, q)
	if err != nil {
		return nil, err
	}

	// Check if the next page token is required.
	var nptOut string
	if len(res.Keys) == q.PageSize && res.Total > int64(q.PageSize)+int64(q.Skip) {
		nptOut, err = pagination.TokenizeStruct[nextPageToken](nextPageToken{
			PageSize: int32(q.PageSize),
			Skip:     int32(q.Skip) + int32(q.PageSize),
		})
		if err != nil {
			return nil, err
		}
	}

	// Compose the response.
	out := &authzadminv1alpha.ListKeysResponse{
		Keys:          make([]*authzadminv1alpha.Key, len(res.Keys)),
		NextPageToken: nptOut,
	}

	for i, key := range res.Keys {
		var rp *durationpb.Duration
		if key.RotationPeriod != 0 {
			rp = durationpb.New(key.RotationPeriod)
		}
		var lr *timestamppb.Timestamp
		if !key.LastRotatedAt.IsZero() {
			lr = timestamppb.New(key.LastRotatedAt)
		}
		out.Keys[i] = &authzadminv1alpha.Key{
			Name:            types.ComposeKeyName(pID, key.ID).String(),
			Uid:             key.ID,
			Algorithm:       signalgpb.SigningAlgorithm(key.Algorithm),
			DisplayName:     key.DisplayName,
			CreateTime:      timestamppb.New(key.CreatedAt),
			UpdateTime:      timestamppb.New(key.UpdatedAt),
			LastRotatedTime: lr,
			RotationPeriod:  rp,
			Priority:        int32(key.Priority),
			Revisions:       int32(key.Revisions),
		}
	}

	return out, nil
}

func (h *KeysHandler) validateListKeys(ctx context.Context, req *authzadminv1alpha.ListKeysRequest) (nextPageToken, error) {
	var br errdetails.BadRequest
	if req.Parent == "" {
		// s := status.New(codes.InvalidArgument, "missing required field")
		// br, err := s.WithDetails(&errdetails.BadRequest{
		// 	FieldViolations: []*errdetails.BadRequest_FieldViolation{
		// 		{
		// 			Field:       "parent",
		// 			Description: "parent is required",
		// 		},
		// 	},
		// })
		// if err != nil {
		// 	return s.Err()
		// }
		// return br.Err()
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

// UpdateKey implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysHandler) UpdateKey(ctx context.Context, req *authzadminv1alpha.UpdateKeyRequest) (*authzadminv1alpha.Key, error) {
	if err := h.validateUpdateKey(ctx, req); err != nil {
		return nil, err
	}

	x, err := h.updateKey.fmp.ParseUpdateExpr(req.Key, req.UpdateMask)
	if err != nil {
		return nil, err
	}

	defer x.Free()

	kn := types.KeyName(req.Name)

	key, err := h.admin.UpdateKey(ctx, admin.UpdateKeyQuery{
		ProjectID: kn.Project(),
		KeyID:     kn.Key(),
		Expr:      x,
	})
	if err != nil {
		return nil, err
	}

	// Recompose key name, as the input could have an alias.
	kn = types.ComposeKeyName(key.ProjectID, key.ID)

	var rp *durationpb.Duration
	if key.RotationPeriod != 0 {
		rp = durationpb.New(key.RotationPeriod)
	}

	var lr *timestamppb.Timestamp
	if !key.LastRotatedAt.IsZero() {
		lr = timestamppb.New(key.LastRotatedAt)
	}

	return &authzadminv1alpha.Key{
		Name:            kn.String(),
		Uid:             key.ID,
		Algorithm:       signalgpb.SigningAlgorithm(key.Algorithm),
		DisplayName:     key.DisplayName,
		CreateTime:      timestamppb.New(key.CreatedAt),
		UpdateTime:      timestamppb.New(key.UpdatedAt),
		LastRotatedTime: lr,
		RotationPeriod:  rp,
		Priority:        int32(key.Priority),
		Revisions:       int32(key.Revisions),
	}, nil
}

func (h *KeysHandler) validateUpdateKey(ctx context.Context, req *authzadminv1alpha.UpdateKeyRequest) error {
	var br errdetails.BadRequest
	if req.Key == nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "key",
			Description: "field is required",
		})
	}

	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "field is required",
		})
	} else {
		kn := types.KeyName(req.Name)
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

	k := req.Key
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

// CreateKeyRevision implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysHandler) CreateKeyRevision(ctx context.Context, req *authzadminv1alpha.CreateKeyRevisionRequest) (*authzadminv1alpha.KeyRevision, error) {
	if err := h.validateCreateKeyRevision(ctx, req); err != nil {
		return nil, err
	}

	kn := types.KeyName(req.Parent)

	rev, err := h.admin.CreateKeyRevision(ctx, admin.CreateKeyRevisionQuery{
		ProjectID: kn.Project(),
		KeyID:     kn.Key(),
	})
	if err != nil {
		return nil, err
	}

	// Compose key revision name.
	krn := types.ComposeKeyRevisionName(kn.Project(), kn.Key(), rev.ID)

	return &authzadminv1alpha.KeyRevision{
		Name:           krn.String(),
		Kid:            rev.ID,
		CreateTime:     timestamppb.New(rev.CreatedAt),
		RevisionNumber: int32(rev.Revision),
	}, nil
}

func (h *KeysHandler) validateCreateKeyRevision(ctx context.Context, req *authzadminv1alpha.CreateKeyRevisionRequest) error {
	var br errdetails.BadRequest
	if req.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "field is required",
		})
	} else {
		pn := types.KeyName(req.Parent)
		if err := pn.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "parent",
				Description: err.Error(),
			})
		}
	}

	if req.Revision == nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "revision",
			Description: "field is required",
		})
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

// GetKeyRevision implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysHandler) GetKeyRevision(ctx context.Context, req *authzadminv1alpha.GetKeyRevisionRequest) (*authzadminv1alpha.KeyRevision, error) {
	if err := h.validateGetKeyRevision(req); err != nil {
		return nil, err
	}

	krn := types.KeyRevisionName(req.Name)

	rev, err := h.admin.GetKeyRevision(ctx, admin.GetKeyRevisionQuery{
		ProjectID:     krn.Project(),
		KeyID:         krn.Key(),
		KeyRevisionID: krn.Revision(),
	})
	if err != nil {
		return nil, err
	}

	krn = types.ComposeKeyRevisionName(rev.ProjectID, rev.KeyID, rev.ID)
	var rt *timestamppb.Timestamp
	if !rev.RevokedAt.IsZero() {
		rt = timestamppb.New(rev.RevokedAt)
	}

	return &authzadminv1alpha.KeyRevision{
		Name:           krn.String(),
		Kid:            rev.ID,
		CreateTime:     timestamppb.New(rev.CreatedAt),
		RevisionNumber: int32(rev.Revision),
		RevokeTime:     rt,
	}, nil
}

// ListKeyRevisions implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysHandler) ListKeyRevisions(ctx context.Context, req *authzadminv1alpha.ListKeyRevisionsRequest) (*authzadminv1alpha.ListKeyRevisionsResponse, error) {
	npt, err := h.validateListKeyRevisions(ctx, req)
	if err != nil {
		return nil, err
	}

	keyName := types.KeyName(req.Parent)

	q := admin.ListKeyRevisionsQuery{
		ProjectID: keyName.Project(),
		KeyID:     keyName.Key(),
		PageSize:  int(req.PageSize),
	}
	if req.PageToken != "" {
		q.PageSize = int(npt.PageSize)
		q.Skip = int(npt.Skip)
	} else if q.PageSize == 0 {
		q.PageSize = int(h.listKeyRevisions.pageSize)
	}

	q.OrderBy = h.listKeyRevisions.orderBy

	res, err := h.admin.ListKeyRevisions(ctx, q)
	if err != nil {
		return nil, err
	}

	// Check if the next page token is required.
	var nptOut string
	if len(res.KeyRevisions) == q.PageSize && res.Total > int64(q.PageSize)+int64(q.Skip) {
		nptOut, err = pagination.TokenizeStruct[nextPageToken](nextPageToken{
			PageSize: int32(q.PageSize),
			Skip:     int32(q.Skip) + int32(q.PageSize),
		})
		if err != nil {
			h.log.ErrorContext(ctx, "failed to tokenize next page token", "error", err)
		}
	}

	out := authzadminv1alpha.ListKeyRevisionsResponse{NextPageToken: nptOut}
	if len(res.KeyRevisions) > 0 {
		out.KeyRevisions = make([]*authzadminv1alpha.KeyRevision, len(res.KeyRevisions))
		for i, rev := range res.KeyRevisions {
			var rt *timestamppb.Timestamp
			if !rev.RevokedAt.IsZero() {
				rt = timestamppb.New(rev.RevokedAt)
			}

			revName := types.ComposeKeyRevisionName(rev.ProjectID, rev.KeyID, rev.ID)
			out.KeyRevisions[i] = &authzadminv1alpha.KeyRevision{
				Name:           revName.String(),
				Kid:            rev.ID,
				CreateTime:     timestamppb.New(rev.CreatedAt),
				RevisionNumber: int32(rev.Revision),
				RevokeTime:     rt,
			}
		}
	}

	return &out, nil
}

func (h *KeysHandler) validateListKeyRevisions(ctx context.Context, req *authzadminv1alpha.ListKeyRevisionsRequest) (nextPageToken, error) {
	var br errdetails.BadRequest
	if req.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "field is required",
		})
	} else {
		pn := types.KeyName(req.Parent)
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

func (h *KeysHandler) validateGetKeyRevision(req *authzadminv1alpha.GetKeyRevisionRequest) error {
	var br errdetails.BadRequest
	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "field is required",
		})
	} else {
		krn := types.KeyRevisionName(req.Name)
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

// RevokeKeyRevision implements authzadminv1alpha.KeyAdminServiceServer.
func (h *KeysHandler) RevokeKeyRevision(ctx context.Context, req *authzadminv1alpha.RevokeKeyRevisionRequest) (*authzadminv1alpha.KeyRevision, error) {
	if err := h.validateRevokeKeyRevision(ctx, req); err != nil {
		return nil, err
	}

	krn := types.KeyRevisionName(req.Name)
	rev, err := h.admin.RevokeKeyRevision(ctx, admin.RevokeKeyRevisionQuery{
		ProjectID:          krn.Project(),
		KeyIdentifier:      krn.Key(),
		RevisionIdentifier: krn.Revision(),
	})
	if err != nil {
		return nil, err
	}

	krn = types.ComposeKeyRevisionName(rev.ProjectID, rev.KeyID, rev.ID)
	return &authzadminv1alpha.KeyRevision{
		Name:           krn.String(),
		Kid:            rev.ID,
		CreateTime:     timestamppb.New(rev.CreatedAt),
		RevisionNumber: int32(rev.Revision),
		RevokeTime:     timestamppb.New(rev.RevokedAt),
	}, nil
}

func (h *KeysHandler) validateRevokeKeyRevision(ctx context.Context, req *authzadminv1alpha.RevokeKeyRevisionRequest) error {
	var br errdetails.BadRequest
	if req.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "field is required",
		})
	} else {
		krn := types.KeyRevisionName(req.Name)
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
