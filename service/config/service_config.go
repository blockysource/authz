// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"time"

	"github.com/blockysource/authz/types/signalg"
)

// ConfigProvider is a struct to hold the configuration provider.
type ConfigProvider struct {
	Service ServiceConfig
}

// GetServiceConfig is a method to get the service configuration.
func (c *ConfigProvider) GetServiceConfig() ServiceConfig {
	return c.Service
}



// ServiceConfig is a struct to hold the service configuration.
type ServiceConfig struct {
	// Issuer is the issuer name of the service.
	Issuer            string

	// DefaultKeyID is the default key id of the service.
	// This is an identifier of the key, not its revision.
	DefaultKeyID      string

	// FavoredAlgorithms is the favored algorithms of the service.
	FavoredAlgorithms []signalg.SigningAlgorithm

	// KeyRotationPeriod is the key rotation period of the service.
	KeyRotationPeriod time.Duration
}
