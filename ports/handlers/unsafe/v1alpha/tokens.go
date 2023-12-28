// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package v1alpha

import (
	"context"
	"github.com/blockysource/authz/cache"
	"github.com/blockysource/authz/logic/keys"
	"github.com/blockysource/authz/logic/tokens"
	localtypes "github.com/blockysource/authz/types/local"
	"log/slog"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/blockysource/authz/persistence/localdb"
	"github.com/blockysource/authz/types"
	"github.com/blockysource/authz/types/algorithm"
	"github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"
	authzunsafev1alpha "github.com/blockysource/go-genproto/blocky/authz/unsafe/v1alpha"
)

// TokensHandler is a handler for tokens service.
type TokensHandler struct {
	authzunsafev1alpha.UnimplementedTokensServiceServer

	log     *slog.Logger
	ic      *cache.InstancesContainer
	keySets *cache.KeySetsContainer
	is      *localdb.InstancesStorage
	rs      *cache.ResourcesContainer
	tokens  tokens.JwtTokenIssueSigner
}

// IssueToken implements authzunsafev1alpha.TokensServiceServer.
// It is responsible for issuing a token for a given request.
func (h *TokensHandler) IssueToken(ctx context.Context, in *authzunsafev1alpha.IssueTokenRequest) (*authzunsafev1alpha.IssueTokenResponse, error) {
	if err := h.issueTokenValidateInput(ctx, in); err != nil {
		return nil, err
	}

	projectName := types.ProjectName(in.Project)

	project := projectName.Project()
	ks, ok := h.keySets.GetProjectKeySet(project)
	if !ok {
		// This project is not found. Return an error.
		return nil, projectNotFoundError(in.Project)
	}

	is, ok := h.ic.GetInstance(project)
	if !ok {
		// This means that project instance are not initialized well, once key set container contains the project.
		h.log.WarnContext(ctx, "project instances out of sync, project not found", "project", project)

		// TODO: send internal service notification that project instances needs to be updated.
		// This should be done by simply using a channel (this does not need to get out of this instance).

		return nil, status.Error(codes.Unavailable, "service out of sync, retry with backoff")
	}

	rs, ok := h.rs.FindProjectResources(project)
	if !ok {
		// This means that project resources are not initialized well, once other containers contain the project.
		h.log.WarnContext(ctx, "project resources out of sync, project not found", "project", project)

		// TODO: send internal service notification that project instances needs to be updated.
		// This should be done by simply using a channel (this does not need to get out of this instance).

		return nil, status.Error(codes.Unavailable, "service out of sync, retry with backoff")
	}

	// Check if the key is specified in the request. If so, then try to get key out of the key set.
	var sk *keys.SigningKey
	if in.Key != "" {
		sk, ok = ks.FindSigningKey(in.Key)
		if !ok {
			// This key is not found. Return an error.
			s := status.New(codes.NotFound, "key not found")
			sb, err := s.WithDetails(&errdetails.ResourceInfo{
				ResourceType: "authz.blockyapis.com/Key",
				ResourceName: in.Key,
			})
			if err != nil {
				return nil, s.Err()
			}
			return nil, sb.Err()
		}
	} else if in.Algorithm != signalgpb.SigningAlgorithm_SIGNING_ALGORITHM_UNSPECIFIED {
		// If the algorithm is specified, then
		alg := algorithm.SigningAlgorithm(in.Algorithm)
		sk, ok = ks.FindHighestPrioritySigningKeyByAlgorithm(alg)
		if !ok {
			// No matching algorithm found in the key set. Return an error.
			s := status.New(codes.FailedPrecondition, "no matching key found for given algorithm")
			sb, err := s.WithDetails(&errdetails.PreconditionFailure{
				Violations: []*errdetails.PreconditionFailure_Violation{
					{
						Type:        "authz.blockyapis.com/Key",
						Subject:     "signing algorithm",
						Description: "no matching key with given algorithm defined",
					},
				},
			})
			if err != nil {
				return nil, s.Err()
			}
			return nil, sb.Err()
		}
	} else if in.Client != "" {
		// TODO: If the client is specified, get favourite algorithm from the client definition.
	} else {
		// Get the highest priority key, that matches instance default algorithm.
		sk, ok = ks.FindHighestPrioritySigningKeyByAlgorithm(is.AccessTokenConfig.FavoredAlgorithm)
		if !ok {
			// No matching algorithm found in the key set. Return an error.
			s := status.New(codes.FailedPrecondition, "no matching key found for given algorithm")
			sb, err := s.WithDetails(&errdetails.PreconditionFailure{
				Violations: []*errdetails.PreconditionFailure_Violation{
					{
						Type:        "authz.blockyapis.com/Key",
						Subject:     "signing algorithm",
						Description: "no matching key with given algorithm defined",
					},
				},
			})
			if err != nil {
				return nil, s.Err()
			}
			return nil, sb.Err()
		}
	}

	var aud tokens.Audience
	for _, scope := range strings.Split(in.Scope, " ") {
		// Get the resource manager for the scope.
		var rm *localtypes.ResourceManager
		rm, ok = rs.FindManagerByScope(scope)
		if !ok {
			// This scope is undefined in current resources. Return an error.
			s := status.New(codes.FailedPrecondition, "scope not found")
			sb, err := s.WithDetails(&errdetails.PreconditionFailure{
				Violations: []*errdetails.PreconditionFailure_Violation{
					{
						Type:        "authz.blockyapis.com/ResourcePermission",
						Subject:     scope,
						Description: "scope not found",
					},
				},
			})
			if err != nil {
				return nil, s.Err()
			}
			return nil, sb.Err()
		}

		// Iterate over all

	}

}

func projectNotFoundError(project string) error {
	s := status.New(codes.NotFound, "project not found")
	sb, err := s.WithDetails(&errdetails.ResourceInfo{
		ResourceType: "cloudresourcemanager.blockyapis.com/Project",
		ResourceName: project,
	})
	if err != nil {
		return s.Err()
	}
	return sb.Err()
}

func (h *TokensHandler) issueTokenValidateInput(ctx context.Context, in *authzunsafev1alpha.IssueTokenRequest) error {
	// Parse the project name.
	var br errdetails.BadRequest
	projectName := types.ProjectName(in.Project)
	if err := projectName.Validate(); err != nil {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "project",
			Description: err.Error(),
		})
	}

	// Check if the subject is defined.
	if in.Subject == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "subject",
			Description: "field is required",
		})
	}

	if in.Scope == "" {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{
			Field:       "scope",
			Description: "field is required",
		})
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
