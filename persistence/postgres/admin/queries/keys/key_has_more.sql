-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT 1 AS has_more
FROM blocky_authz_key AS k
WHERE k.project_id = $1
  AND k.created_at > $2

