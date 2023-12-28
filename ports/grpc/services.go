// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package grpcports

import (
	admingrpc "github.com/blockysource/authz/ports/grpc/admin"
	"google.golang.org/grpc"
)

// Services is a container for all standard) gRPC services.
// This does not include unsafe gRPC services.
type Services struct {
	admin *admingrpc.Services
}

// RegisterServices registers all gRPC services.
func (s *Services) RegisterServices(server grpc.ServiceRegistrar) {
	s.admin.RegisterServices(server)
}
