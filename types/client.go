// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package types

import (
	"errors"
	"time"

	"github.com/blockysource/authz/types/algorithm"
	"github.com/blockysource/blocky-aip/names"
)

// ClientType is the client type.
type ClientType int

const (
	// ClientTypePublic is the public client type.
	ClientTypePublic ClientType = 1

	// ClientTypeConfidential is the confidential client type.
	ClientTypeConfidential ClientType = 2
)

// ClientName is the client resource name type.
type ClientName string

// ComposeClientName composes a client name.
func ComposeClientName(project, client string) ClientName {
	return ClientName(ComposeKeyCoreName(project, client).String())
}

// String returns the string representation of the client name.
func (c ClientName) String() string {
	return string(c)
}

// Validate validates the client name.
func (c ClientName) Validate() error {
	n := names.Name(c)

	if n.Parts() != 4 {
		return errors.New("invalid key core name format")
	}

	if n.Part(0) != "projects" {
		return errors.New("invalid client name no projects resources name")
	}

	if n.Part(1) == "" {
		return errors.New("invalid client name no project resource identifier")
	}

	if n.Part(2) != "clients" {
		return errors.New("invalid client name no 'clients' resources name")
	}

	if n.Part(3) == "" {
		return errors.New("invalid client name no 'client' resource identifier")
	}
	return nil
}

// Client returns the identifier of the client.
func (c ClientName) Client() string {
	return names.Name(c).Part(3)
}

// Project returns the identifier of the project.
func (c ClientName) Project() string {
	return names.Name(c).Part(1)
}

// Client represents an authorization client.
type Client struct {
	// ID is the unique identifier of the client.
	ID string

	// ProjectID is the project identifier of the client.
	ProjectID string

	// CreatedAt is the time when the client was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the client was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the client.
	DisplayName string

	// Alias is the alias of the client.
	Alias string

	// Type is the type of the client.
	Type ClientType

	// OrganizationInternal denotes if the client is an internal client for the project organization.
	OrganizationInternal bool
}

// ClientAlgorithm is the client preference of the algorithm.
type ClientAlgorithm struct {
	// Algorithm is the algorithm of the client.
	Algorithm algorithm.SigningAlgorithm

	// Priority is the priority of the algorithm.
	Priority int
}

type ClientCredentials struct {
	// ClientID is the unique identifier of the client.
	ClientID string

	// ProjectID is the project identifier of the client.
	ProjectID string

	// EncryptedSecret is the encrypted secret.
	EncryptedSecret []byte
}
