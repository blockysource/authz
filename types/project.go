// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package types

import (
	"errors"

	"github.com/blockysource/blocky-aip/names"
)

// ProjectName is the resource name of the authorization project.
type ProjectName string

// Validate validates the project name.
func (p ProjectName) Validate() error {
	nm := names.Name(p)
	if nm.Part(0) != "projects" {
		return errors.New("invalid project name no projects resources name")
	}
	if nm.Part(1) == "" {
		return errors.New("invalid project name no project resource identifier")
	}
	return nil
}

// Project returns the identifier of the project.
// This doesn't validate the project name, thus for invalid project names it
// may return invalid project identifier.
func (p ProjectName) Project() string {
	return names.Name(p).Part(1)
}
