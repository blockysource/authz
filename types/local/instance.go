// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package localtypes

import (
	"time"

	"github.com/blockysource/authz/types/algorithm"
)

type (
	// Instance represents an instance of a project.
	Instance struct {
		// ID is the unique identifier of the instance.
		ID string

		// CreatedAt is the time when the instance was created.
		CreatedAt time.Time

		// UpdatedAt is the time when the instance was last updated.
		UpdatedAt time.Time

		// DisplayName is the display name of the instance.
		DisplayName string

		// ProjectID is the project identifier of the instance.
		ProjectID string

		// AccessTokenConfig is the access token config of the instance.
		AccessTokenConfig InstanceAccessTokenConfig

		// RefreshTokenConfig is the refresh token config of the instance.
		RefreshTokenConfig InstanceRefreshTokenConfig
	}
	// InstanceAccessTokenConfig represents an access token config of an instance.
	InstanceAccessTokenConfig struct {
		// FavoredAlgorithm is the favored algorithm of the access token.
		FavoredAlgorithm algorithm.SigningAlgorithm

		// TokenLifetime is the lifetime of the access token.
		TokenLifetime time.Duration
	}

	// InstanceRefreshTokenConfig represents a refresh token config of an instance.
	InstanceRefreshTokenConfig struct {
		// FavoredAlgorithm is the favored algorithm of the refresh token.
		FavoredAlgorithm algorithm.SigningAlgorithm

		// TokenLifetime is the lifetime of the refresh token.
		TokenLifetime time.Duration

		// TokenSize is the bytes size of the refresh token.
		TokenSize int
	}
)
