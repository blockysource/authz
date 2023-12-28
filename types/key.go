// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package types

import (
	"errors"
	"time"

	"github.com/blockysource/authz/persistence/driver/algorithmdb"
	"github.com/blockysource/blocky-aip/names"
)

// KeyCoreName is the resource name of the authorization key.
// The format of the key name is:
// 'projects/{project}/keyCores/{key_core}
type KeyCoreName string

// ComposeKeyCoreName composes a key name.
func ComposeKeyCoreName(project, keyCore string) KeyCoreName {
	var c names.Composer
	c.WritePart("projects")
	c.WritePart(project)
	c.WritePart("keyCores")
	c.WritePart(keyCore)

	return KeyCoreName(c.Name())
}

// String returns the string representation of the key name.
func (k KeyCoreName) String() string {
	return string(k)
}

// Validate validates the key name.
func (k KeyCoreName) Validate() error {
	n := names.Name(k)

	if n.Parts() != 4 {
		return errors.New("invalid key core name format")
	}

	if n.Part(0) != "projects" {
		return errors.New("invalid key core name no projects resources name")
	}

	if n.Part(1) == "" {
		return errors.New("invalid key core name no project resource identifier")
	}

	if n.Part(2) != "keyCores" {
		return errors.New("invalid key core name no keys resources name")
	}

	if n.Part(3) == "" {
		return errors.New("invalid key core name no key core resource identifier")
	}

	return nil
}

// KeyCore returns the identifier of the key.
// This doesn't validate the key name, thus for invalid key names it
// may return invalid key identifier.
func (k KeyCoreName) KeyCore() string {
	return names.Name(k).Part(-1)
}

// Project returns the identifier of the project.
// This doesn't validate the key name, thus for invalid key names it
// may return invalid project identifier.
func (k KeyCoreName) Project() string {
	return names.Name(k).Part(1)
}

// KeyName is the resource name of the authorization key.
// The format of the key name is:
// 'projects/{project}/keys/{key}
type KeyName string

// ComposeKeyName composes a key revision name.
func ComposeKeyName(project, key string) KeyName {
	var c names.Composer
	c.WritePart("projects")
	c.WritePart(project)
	c.WritePart("keys")
	c.WritePart(key)
	return KeyName(c.Name())
}

// Validate validates the key revision name.
func (k KeyName) Validate() error {
	n := names.Name(k)
	if n.Part(0) != "projects" {
		return errors.New("invalid key name no projects resources name")
	}

	if n.Part(1) == "" {
		return errors.New("invalid key name no project resource identifier")
	}

	if n.Part(2) != "keyCores" {
		return errors.New("invalid key name no keys resources name")
	}

	if n.Part(3) == "" {
		return errors.New("invalid key name no key resource identifier")
	}

	return nil
}

// Project returns the identifier of the project.
// This doesn't validate the key revision name, thus for invalid key revision names it
// may return invalid project identifier.
func (k KeyName) Project() string {
	return names.Name(k).Part(1)
}

// Key returns the identifier of the key.
// This doesn't validate the key revision name, thus for invalid key revision names it
// may return invalid key identifier.
func (k KeyName) Key() string {
	return names.Name(k).Part(-1)
}

// String returns the string representation of the key revision name.
func (k KeyName) String() string {
	return string(k)
}

// KeyCore represents a key core.
type KeyCore struct {
	// ID is the unique identifier of the key core.
	ID string

	// ProjectID is the project identifier of the key core.
	ProjectID string

	// CreatedAt is the time when the key was created.
	CreatedAt time.Time

	// UpdatedAt is the time when the key was last updated.
	UpdatedAt time.Time

	// DisplayName is the display name of the key core.
	DisplayName string

	// Algorithm is the signing algorithm of the ke corey.
	Algorithm algorithmdb.SigningAlgorithm

	// LastRotatedAt is the time when the key core was last rotated.
	LastRotatedAt time.Time

	// RotationInterval is the rotation period of the key core.
	RotationInterval time.Duration

	// Priority is the priority of the key core.
	Priority int

	// DerivedKeysCount is the number of derived keys that based on this key core.
	DerivedKeysCount int
}

// Key represents a single revision of a key.
type Key struct {
	// ID is the unique identifier of the key revision.
	ID string

	// CoreID is the unique identifier of the key.
	CoreID string

	// ProjectID is the project identifier of the key revision.
	ProjectID string

	// CreatedAt is the time when the key revision was created.
	CreatedAt time.Time

	// Revision is the number of revisions of the key.
	Revision int

	// RevokedAt is the time when the key revision was revoked.
	// If the key revision is not revoked, this is the zero time.
	RevokedAt time.Time
}
