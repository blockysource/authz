// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package unsafegrpc

import (
	unsafev1alpha "github.com/blockysource/authz/ports/handlers/unsafe/v1alpha"
	authzunsafev1alpha "github.com/blockysource/go-genproto/blocky/authz/unsafe/v1alpha"
	"google.golang.org/grpc"
)

// Services is a container of all gRPC unsafe services.
type Services struct {
	tokensV1Alpha *unsafev1alpha.TokensHandler
}

// RegisterEndpoints registers all unsafe gRPC endpoints.
func (h *Services) RegisterEndpoints(unsafeServer grpc.ServiceRegistrar) {
	authzunsafev1alpha.RegisterTokensServiceServer(unsafeServer, h.tokensV1Alpha)
}
