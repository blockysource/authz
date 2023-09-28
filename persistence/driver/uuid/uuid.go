// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package driveruuid

import (
	"database/sql/driver"
	"fmt"

	"github.com/google/uuid"
)

// Nil is the nil UUID.
var Nil = UUID(uuid.Nil)

// UUID is a type for UUID.
type UUID uuid.UUID

// New creates a new UUID.
func New() UUID {
	return UUID(uuid.New())
}

// Parse parses a UUID.
func Parse(s string) (UUID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return UUID{}, err
	}
	return UUID(u), nil
}

// MustParse parses a UUID and panics on error.
func MustParse(s string) UUID {
	u, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// ParseBytes parses a UUID from bytes.
func ParseBytes(b []byte) (UUID, error) {
	u, err := uuid.ParseBytes(b)
	if err != nil {
		return UUID{}, err
	}
	return UUID(u), nil
}

func (u UUID) String() string {
	return uuid.UUID(u).String()
}

// Bytes returns the UUID as bytes.
func (u UUID) Bytes() []byte {
	return u[:]
}

// Value implements the driver.Valuer interface.
func (u *UUID) Value() (driver.Value, error) {
	if u.IsNil() {

	}
	return u.Bytes(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (u *UUID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(u).UnmarshalBinary(data)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (u UUID) MarshalBinary() ([]byte, error) {
	return uuid.UUID(u).MarshalBinary()
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (u *UUID) UnmarshalText(text []byte) error {
	return (*uuid.UUID)(u).UnmarshalText(text)
}

// MarshalText implements the encoding.TextMarshaler interface.
func (u UUID) MarshalText() ([]byte, error) {
	return uuid.UUID(u).MarshalText()
}

// Scan implements the sql.Scanner interface.
func (u *UUID) Scan(src any) error {
	switch st := src.(type) {
	case nil:
		*u = Nil
		return nil
	case []byte:
		return u.UnmarshalBinary(st)
	case string:
		return u.UnmarshalText([]byte(st))
	default:
		return fmt.Errorf("uuid: cannot scan type %T into uuid.UUID", st)
	}
}

// IsNil returns true if the UUID is nil.
func (u UUID) IsNil() bool {
	return u == Nil
}
