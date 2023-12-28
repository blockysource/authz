-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT COUNT(*) AS count
FROM blocky_authz_key AS k
WHERE k.project_id = $1