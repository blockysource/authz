-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

UPDATE blocky_authz_key AS k
SET revoked_at = $3
WHERE k.project_id = $1 AND k.id = $2