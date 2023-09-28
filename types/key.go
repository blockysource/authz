// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package types

import (
	"errors"
	"time"

	"github.com/blockysource/authz/persistence/driver/algorithm"
	"github.com/blockysource/blocky-aip/names"
)

// KeyName is the resource name of the authorization key.
// The format of the key name is:
// 'projects/{project}/keys/{key}
type KeyName string

// ComposeKeyName composes a key name.
func ComposeKeyName(project, key string) KeyName {
	var c names.Composer
	c.WritePart("projects")
	c.WritePart(project)
	c.WritePart("keys")
	c.WritePart(key)

	return KeyName(c.Name())
}

// String returns the string representation of the key name.
func (k KeyName) String() string {
	return string(k)
}

// Validate validates the key name.
func (k KeyName) Validate() error {
	n := names.Name(k)

	if n.Parts() != 4 {
		return errors.New("invalid key name format")
	}

	if n.Part(0) != "projects" {
		return errors.New("invalid key name no projects resources name")
	}

	if n.Part(1) == "" {
		return errors.New("invalid key name no project resource identifier")
	}

	if n.Part(2) != "keys" {
		return errors.New("invalid key name no keys resources name")
	}

	if n.Part(3) == "" {
		return errors.New("invalid key name no key resource identifier")
	}

	return nil
}

// Key returns the identifier of the key.
// This doesn't validate the key name, thus for invalid key names it
// may return invalid key identifier.
func (k KeyName) Key() string {
	return names.Name(k).Part(-1)
}

// Project returns the identifier of the project.
// This doesn't validate the key name, thus for invalid key names it
// may return invalid project identifier.
func (k KeyName) Project() string {
	return names.Name(k).Part(1)
}

// KeyRevisionName is the resource name of the authorization key revision.
// The format of the key revision name is:
// 'projects/{project}/keys/{key}/revisions/{revision}
type KeyRevisionName string

// ComposeKeyRevisionName composes a key revision name.
func ComposeKeyRevisionName(project, key, revision string) KeyRevisionName {
	var c names.Composer
	c.WritePart("projects")
	c.WritePart(project)
	c.WritePart("keys")
	c.WritePart(key)
	c.WritePart("revisions")
	c.WritePart(revision)

	return KeyRevisionName(c.Name())
}

// Validate validates the key revision name.
func (k KeyRevisionName) Validate() error {
	n := names.Name(k)
	if n.Part(0) != "projects" {
		return errors.New("invalid key revision name no projects resources name")
	}

	if n.Part(1) == "" {
		return errors.New("invalid key revision name no project resource identifier")
	}

	if n.Part(2) != "keys" {
		return errors.New("invalid key revision name no keys resources name")
	}

	if n.Part(3) == "" {
		return errors.New("invalid key revision name no key resource identifier")
	}

	if n.Part(4) != "revisions" {
		return errors.New("invalid key revision name no revisions resources name")
	}

	if n.Part(5) == "" {
		return errors.New("invalid key revision name no revision resource identifier")
	}

	return nil
}

// Project returns the identifier of the project.
// This doesn't validate the key revision name, thus for invalid key revision names it
// may return invalid project identifier.
func (k KeyRevisionName) Project() string {
	return names.Name(k).Part(1)
}

// Key returns the identifier of the key.
// This doesn't validate the key revision name, thus for invalid key revision names it
// may return invalid key identifier.
func (k KeyRevisionName) Key() string {
	return names.Name(k).Part(-3)
}

// Revision returns the identifier of the key revision.
// This doesn't validate the key revision name, thus for invalid key revision names it
// may return invalid key revision identifier.
func (k KeyRevisionName) Revision() string {
	return names.Name(k).Part(-1)
}

func (k KeyRevisionName) String() string {
	return string(k)
}

// Key represents a key.
type Key struct {
	// ID is the unique identifier of the key.
	ID string

	// ProjectID is the project identifier of the key.
	ProjectID string

	// CreatedAt is the time when the key was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the key was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the key.
	DisplayName string

	// Algorithm is the signing algorithm of the key.
	Algorithm algorithm.SigningAlgorithm

	// LastRotatedAt is the time when the key was last rotated.
	LastRotatedAt time.Time

	// RotationPeriod is the rotation period of the key.
	RotationPeriod time.Duration

	// Priority is the priority of the key.
	Priority int

	// Revisions is the number of revisions of the key.
	Revisions int
}

// KeyRevision represents a single revision of a key.
type KeyRevision struct {
	// ID is the unique identifier of the key revision.
	ID string

	// KeyID is the unique identifier of the key.
	KeyID string

	// ProjectID is the project identifier of the key revision.
	ProjectID string

	// CreatedAt is the time when the key revision was created.
	CreatedAt time.Time

	// Revision is the number of revisions of the key.
	Revision int

	// RevokedAt is the time when the key revision was revoked.
	RevokedAt time.Time
}

// KeyRevisionSecret represents a single revision of a key with its secret.
type KeyRevisionSecret struct {
	// KeyID is the unique identifier of the key.
	KeyID string

	// RevisionID is the unique identifier of the key revision.
	RevisionID string

	// Priority is the priority of the key.
	Priority int

	// Algorithm is the signing algorithm of the key.
	Algorithm SigningAlgorithm

	// Secret is the secret of the key.
	Secret []byte
}
