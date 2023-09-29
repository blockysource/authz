// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package purge

import (
	"strings"
)

const copyright = `-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1
`

// SanitizeSQL sanitizes the SQL statement.
func SanitizeSQL(inSQL string) string {
	// trim the license header
	return strings.TrimPrefix(inSQL, copyright)
}
