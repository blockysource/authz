// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package clientdb

import (
	"database/sql/driver"
	"errors"

	"github.com/blockysource/authz/types"
)

// ClientType is the client type database representation.
type ClientType int

const (
	// ClientTypePublic is the public client type.
	ClientTypePublic = ClientType(types.ClientTypePublic)
	// ClientTypeConfidential is the confidential client type.
	ClientTypeConfidential = ClientType(types.ClientTypeConfidential)
)

var ErrInvalidClientType = errors.New("invalid client type")

var _ driver.Valuer = ClientType(0)

// Value implements the driver.Valuer interface.
func (c ClientType) Value() (driver.Value, error) {
	if !c.IsValid() {
		return nil, ErrInvalidClientType
	}
	return c.String(), nil
}

// Scan implements the sql.Scanner interface.
func (c *ClientType) Scan(src any) (err error) {
	switch st := src.(type) {
	case string:
		*c, err = ClientTypeFromString(st)
	case []byte:
		*c, err = ClientTypeFromString(string(st))
	}
	return
}

func (c ClientType) String() string {
	switch c {
	case ClientTypePublic:
		return "PUBLIC"
	case ClientTypeConfidential:
		return "CONFIDENTIAL"
	default:
		return "UNKNOWN"
	}
}

// IsValid checks if the client type is valid.
func (c ClientType) IsValid() bool {
	switch c {
	case ClientTypePublic, ClientTypeConfidential:
		return true
	default:
		return false
	}
}

func ClientTypeFromString(src string) (ClientType, error) {
	switch src {
	case "PUBLIC":
		return ClientTypePublic, nil
	case "CONFIDENTIAL":
		return ClientTypeConfidential, nil
	default:
		return ClientType(0), ErrInvalidClientType
	}
}
