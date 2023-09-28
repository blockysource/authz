-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT COUNT(*) AS count
FROM blocky_authz_key_revision AS rev
         JOIN blocky_authz_key_identifier AS ki
              ON rev.key_id = ki.key_id
WHERE ki.project_id = $1
  AND ki.identifier = $2