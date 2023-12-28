// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package adminv1alpha

import (
	"github.com/blockysource/authz/cache"
	"github.com/blockysource/authz/deps"
	"github.com/blockysource/authz/logic/clients"
	"github.com/blockysource/authz/logic/keys"
	"github.com/blockysource/authz/persistence/admindb"
	"github.com/blockysource/go-secret-hash"
	"log/slog"
)

// Injectors from wire.go:

// NewClientsServiceHandler creates a new instance of the ClientsServiceHandler.
func NewClientsServiceHandler(dependencies *deps.Dependencies, containers *cache.Containers) (*ClientsServiceHandler, func(), error) {
	clientsServiceHandler, cleanup, err := newInitedClientsServiceHandler(dependencies, containers)
	if err != nil {
		return nil, nil, err
	}
	return clientsServiceHandler, func() {
		cleanup()
	}, nil
}

// newClientsServiceHandler creates a new instance of the ClientsServiceHandler.
func newClientsServiceHandler(d *deps.Dependencies, cache2 *cache.Containers) (*ClientsServiceHandler, func(), error) {
	handler := deps.ProvideLogger(d)
	logger := newClientsLogger(handler)
	hasher, err := newClientsSecretHasher()
	if err != nil {
		return nil, nil, err
	}
	options := clients.DefaultOptions()
	clientsLogic, err := clients.NewClientsLogic(hasher, options)
	if err != nil {
		return nil, nil, err
	}
	clientsStorage, err := admindb.NewClientsStorage(d)
	if err != nil {
		return nil, nil, err
	}
	clientsServiceHandler := &ClientsServiceHandler{
		log:         logger,
		logic:       clientsLogic,
		persistence: clientsStorage,
	}
	return clientsServiceHandler, func() {
	}, nil
}

// NewKeysServiceHandler creates a new instance of the KeysServiceHandler.
func NewKeysServiceHandler(dependencies *deps.Dependencies, containers *cache.Containers) (*KeysServiceHandler, func(), error) {
	keysServiceHandler, cleanup, err := newInitedKeysServiceHandler(dependencies, containers)
	if err != nil {
		return nil, nil, err
	}
	return keysServiceHandler, func() {
		cleanup()
	}, nil
}

// newKeysServiceHandler creates a new instance of the KeysServiceHandler.
func newKeysServiceHandler(d *deps.Dependencies, cache2 *cache.Containers) (*KeysServiceHandler, func(), error) {
	keysStorage, err := admindb.NewKeysStorage(d)
	if err != nil {
		return nil, nil, err
	}
	signingKeyGenerator := keys.DefaultGenerator()
	handler := deps.ProvideLogger(d)
	logger := newKeysLogger(handler)
	keysServiceHandler := &KeysServiceHandler{
		storage: keysStorage,
		keyGen:  signingKeyGenerator,
		log:     logger,
	}
	return keysServiceHandler, func() {
	}, nil
}

// wire.go:

func newInitedClientsServiceHandler(d *deps.Dependencies, c *cache.Containers) (*ClientsServiceHandler, func(), error) {
	cs, fn, err := newClientsServiceHandler(d, c)
	if err != nil {
		return nil, nil, err
	}

	cs.init()
	return cs, fn, nil
}

func newClientsLogger(h slog.Handler) *slog.Logger {
	return newLogger(h, "clients")
}

func newClientsSecretHasher() (*secrethash.Hasher, error) {
	return secrethash.NewHasher(secrethash.DefaultArgon2HashingAlgorith())
}

func newInitedKeysServiceHandler(d *deps.Dependencies, c *cache.Containers) (*KeysServiceHandler, func(), error) {
	ks, fn, err := newKeysServiceHandler(d, c)
	if err != nil {
		return nil, nil, err
	}

	ks.init()
	return ks, fn, nil
}

func newKeysLogger(h slog.Handler) *slog.Logger {
	return newLogger(h, "keys")
}

func newLogger(h slog.Handler, handler string) *slog.Logger {
	l := slog.New(h)
	return l.With(slog.String("service", "authz"), slog.String("component", "admin"), slog.String("handler", handler))
}
