package persistence

import (
	"database/sql"
)

// Conn is a connection to the database for a specific driver.
// This allows the service to set driver-specific query parameter values.
type Conn struct {
	DriverName string
	Conn       *sql.DB
}
