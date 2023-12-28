// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package admingrpc

import (
	adminv1alpha "github.com/blockysource/authz/ports/handlers/admin/v1alpha"
	authzadminv1alpha "github.com/blockysource/go-genproto/blocky/authz/admin/v1alpha"
	"google.golang.org/grpc"
)

// Services is a container of all admin gRPC services.
type Services struct {
	keys    keysServices
	clients clientsServices
}

type keysServices struct {
	v1Alpha *adminv1alpha.KeysServiceHandler
}

type clientsServices struct {
	v1Alpha *adminv1alpha.ClientsServiceHandler
}

// RegisterServices registers all gRPC endpoints.
func (h *Services) RegisterServices(server grpc.ServiceRegistrar) {
	authzadminv1alpha.RegisterKeyAdminServiceServer(server, h.keys.v1Alpha)
	authzadminv1alpha.RegisterClientAdminServiceServer(server, h.clients.v1Alpha)
}

