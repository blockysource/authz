// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package adminv1alpha

import (
	"context"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blockysource/authz/logic/clients"
	"github.com/blockysource/authz/persistence/admindb"
	"github.com/blockysource/authz/types"
	"github.com/blockysource/blocky-aip/expr"
	"github.com/blockysource/blocky-aip/fieldmask"
	"github.com/blockysource/blocky-aip/ordering"
	blockyannnotations "github.com/blockysource/go-genproto/blocky/api/annotations"
	authzadminv1alpha "github.com/blockysource/go-genproto/blocky/authz/admin/v1alpha"
	secrethash "github.com/blockysource/go-secret-hash"
)

// ClientsServiceHandler is the handler of the clients service.
type ClientsServiceHandler struct {
	authzadminv1alpha.UnimplementedClientAdminServiceServer `wire:"-"`

	log         *slog.Logger
	logic       *clients.ClientsLogic
	persistence *admindb.ClientsStorage

	listClients, listPermissions, listAlgorithms struct {
		orderBy       *expr.OrderByExpr
		pageSize      int32
		maxPageSize   int32
		maxComplexity int64
	} `wire:"-"`

	updateClient struct {
		fmp fieldmask.Parser
	} `wire:"-"`
}

func (h *ClientsServiceHandler) init() {
	// Initialize the key handler parameters from the file descriptor.
	svc := authzadminv1alpha.File_blocky_authz_admin_v1alpha_key_admin_proto.Services().
		ByName("ClientAdminService")
	if svc == nil {
		panic("key admin service not found")
	}

	h.initListClients(svc.Methods().ByName("ListClients"))
	h.initListPermissions(svc.Methods().ByName("ListClientResourcePermissions"))
	h.initListAlgorithms(svc.Methods().ByName("ListClientAlgorithms"))
	h.initUpdateClient()
}

// CreateClient creates an authorization client.
// Implements the CreateClient method of the authzadminv1alpha.ClientAdminServiceServer.
func (h *ClientsServiceHandler) CreateClient(ctx context.Context, in *authzadminv1alpha.CreateClientRequest) (*authzadminv1alpha.Client, error) {
	if err := h.validateCreateClient(ctx, in); err != nil {
		return nil, err
	}

	name := types.ProjectName(in.GetParent())

	id, err := h.logic.GenerateIdentifier()
	if err != nil {
		h.log.Error("failed to generate client identifier", "error", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	client := in.Client

	pc := admindb.CreateClient{
		ProjectID:            name.Project(),
		ClientID:             id,
		DisplayName:          client.DisplayName,
		Alias:                client.Alias,
		OrganizationInternal: client.OrganizationInternal,
	}
	var secret []byte
	if client.ClientType == authzadminv1alpha.ClientType_CONFIDENTIAL {
		pc.Type = types.ClientTypeConfidential

		secret, err = h.logic.GenerateSecret()
		if err != nil {
			h.log.Error("failed to generate client secret", "error", err)
			return nil, status.Error(codes.Internal, "internal error")
		}

		var secretHash secrethash.SecretHash
		secretHash, err = h.logic.HashSecret(secret)
		if err != nil {
			h.log.Error("failed to hash client secret", "error", err)
			return nil, status.Error(codes.Internal, "internal error")
		}

		pc.SecretHash = secretHash.Format()
	} else {
		pc.Type = types.ClientTypePublic
	}

	cc, err := h.persistence.CreateClient(ctx, pc)
	if err != nil {
		return nil, err
	}

	cn := types.ComposeClientName(cc.ProjectID, cc.ID)
	out := authzadminv1alpha.Client{
		Name:                 cn.String(),
		Alias:                cc.Alias,
		ClientId:             cc.ID,
		ClientType:           h.convertClientType(cc.Type),
		DisplayName:          cc.DisplayName,
		CreateTime:           timestamppb.New(cc.CreatedAt),
		UpdateTime:           timestamppb.New(cc.UpdatedAt),
		OrganizationInternal: cc.OrganizationInternal,
		SecretData:           secret,
	}

	return &out, nil
}

func (h *ClientsServiceHandler) validateCreateClient(ctx context.Context, in *authzadminv1alpha.CreateClientRequest) error {
	var br errdetails.BadRequest
	if in.Client == nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "client",
			Description: "field is required",
		})
	}

	if in.Parent == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "parent",
			Description: "field is required",
		})
	} else {
		name := types.ProjectName(in.GetParent())
		if err := name.Validate(); err != nil {
			br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
				Field:       "parent",
				Description: err.Error(),
			})
		}
	}

	c := in.Client
	if c == nil {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}

		st := status.New(codes.InvalidArgument, "invalid input")
		sb, err := st.WithDetails(&br)
		if err != nil {
			return st.Err()
		}
		return sb.Err()
	}

	if c.Name != "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "client.name",
			Description: "field is an identifier and cannot be set as an input",
		})
	}

	if c.ClientType == authzadminv1alpha.ClientType_CLIENT_TYPE_UNSPECIFIED {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "client.client_type",
			Description: "field is required",
		})
	}
	if len(br.FieldViolations) > 0 {
		if h.log.Enabled(ctx, slog.LevelDebug) {
			h.log.DebugContext(ctx, "invalid input", "error", protojson.Format(&br))
		}

		st := status.New(codes.InvalidArgument, "invalid input")
		sb, err := st.WithDetails(&br)
		if err != nil {
			return st.Err()
		}
		return sb.Err()
	}

	return nil
}

// GetClient gets an authorization client.
// Implements the GetClient method of the authzadminv1alpha.ClientAdminServiceServer.
func (h *ClientsServiceHandler) GetClient(ctx context.Context, in *authzadminv1alpha.GetClientRequest) (*authzadminv1alpha.Client, error) {
	if err := h.validateGetClient(ctx, in); err != nil {
		return nil, err
	}

	name := types.ClientName(in.GetName())

	// GetClient gets a single client that matches the given query.
	cc, err := h.persistence.GetClient(ctx, admindb.GetClientQuery{
		ProjectID:        name.Project(),
		ClientIdentifier: name.Client(),
	})
	if err != nil {
		return nil, err
	}

	out := authzadminv1alpha.Client{
		Name:                 name.String(),
		Alias:                cc.Alias,
		ClientId:             cc.ID,
		ClientType:           h.convertClientType(cc.Type),
		DisplayName:          cc.DisplayName,
		CreateTime:           timestamppb.New(cc.CreatedAt),
		UpdateTime:           timestamppb.New(cc.UpdatedAt),
		OrganizationInternal: cc.OrganizationInternal,
	}

	return &out, nil
}

func (h *ClientsServiceHandler) convertClientType(in types.ClientType) authzadminv1alpha.ClientType {
	switch in {
	case types.ClientTypeConfidential:
		return authzadminv1alpha.ClientType_CONFIDENTIAL
	case types.ClientTypePublic:
		return authzadminv1alpha.ClientType_PUBLIC
	default:
		return authzadminv1alpha.ClientType_CLIENT_TYPE_UNSPECIFIED
	}
}

func (h *ClientsServiceHandler) validateGetClient(ctx context.Context, in *authzadminv1alpha.GetClientRequest) error {
	var br errdetails.BadRequest
	if in.Name == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "name",
			Description: "field is required",
		})
	} else {
		name := types.ClientName(in.GetName())
		if err := name.Validate(); err != nil {
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

		st := status.New(codes.InvalidArgument, "invalid input")
		sb, err := st.WithDetails(&br)
		if err != nil {
			return st.Err()
		}
		return sb.Err()
	}

	return nil
}

func (h *ClientsServiceHandler) initListClients(listClientsMethod protoreflect.MethodDescriptor) {
	if listClientsMethod == nil {
		panic("ClientAdminService.ListClients method not found")
	}

	qp, ok := proto.GetExtension(listClientsMethod.Options(), blockyannnotations.E_QueryParams).(*blockyannnotations.QueryParameters)
	if !ok {
		panic("ClientAdminService.ListClients method has no QueryParameters extension")
	}

	clientDesc := new(authzadminv1alpha.Client).ProtoReflect()
	op, err := ordering.NewParser(clientDesc.Descriptor())
	if err != nil {
		panic("ClientAdminService.ListClients method has invalid ordering parameters: " + err.Error())
	}

	h.listClients.orderBy, err = op.Parse(qp.GetOrderBy())
	if err != nil {
		panic("ClientAdminService.ListClients method has invalid ordering parameters: " + err.Error())
	}

	if qp.Pagination != nil {
		h.listClients.pageSize = int32(qp.Pagination.DefaultSize)
		h.listClients.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listClients.maxComplexity = qp.MaxComplexity
}

func (h *ClientsServiceHandler) initListPermissions(listClientPermissions protoreflect.MethodDescriptor) {
	if listClientPermissions == nil {
		panic("ClientAdminService.ListClientPermissions method not found")
	}

	qp, ok := proto.GetExtension(listClientPermissions.Options(), blockyannnotations.E_QueryParams).(*blockyannnotations.QueryParameters)
	if !ok {
		panic("ClientAdminService.ListClientPermissions method has no QueryParameters extension")
	}

	clientDesc := new(authzadminv1alpha.Client).ProtoReflect()
	op, err := ordering.NewParser(clientDesc.Descriptor())
	if err != nil {
		panic("ClientAdminService.ListClientPermissions method has invalid ordering parameters: " + err.Error())
	}

	h.listPermissions.orderBy, err = op.Parse(qp.GetOrderBy())
	if err != nil {
		panic("ClientAdminService.ListClientPermissions method has invalid ordering parameters: " + err.Error())
	}

	if qp.Pagination != nil {
		h.listPermissions.pageSize = int32(qp.Pagination.DefaultSize)
		h.listPermissions.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listPermissions.maxComplexity = qp.MaxComplexity
}

func (h *ClientsServiceHandler) initListAlgorithms(listClientAlgorithms protoreflect.MethodDescriptor) {
	if listClientAlgorithms == nil {
		panic("ClientAdminService.ListClientAlgorithms method not found")
	}

	qp, ok := proto.GetExtension(listClientAlgorithms.Options(), blockyannnotations.E_QueryParams).(*blockyannnotations.QueryParameters)
	if !ok {
		panic("ClientAdminService.ListClientAlgorithms method has no QueryParameters extension")
	}

	clientDesc := new(authzadminv1alpha.Client).ProtoReflect()
	op, err := ordering.NewParser(clientDesc.Descriptor())
	if err != nil {
		panic("ClientAdminService.ListClientAlgorithms method has invalid ordering parameters: " + err.Error())
	}

	h.listAlgorithms.orderBy, err = op.Parse(qp.GetOrderBy())
	if err != nil {
		panic("ClientAdminService.ListClientAlgorithms method has invalid ordering parameters: " + err.Error())
	}

	if qp.Pagination != nil {
		h.listAlgorithms.pageSize = int32(qp.Pagination.DefaultSize)
		h.listAlgorithms.maxPageSize = int32(qp.Pagination.MaxSize)
	}
	h.listAlgorithms.maxComplexity = qp.MaxComplexity

}

func (h *ClientsServiceHandler) initUpdateClient() {
	var fmp fieldmask.Parser
	err := fmp.Reset(new(authzadminv1alpha.Client), fieldmask.IgnoreNonUpdatableOption)
	if err != nil {
		panic(err)
	}
	h.updateClient.fmp = fmp
}
