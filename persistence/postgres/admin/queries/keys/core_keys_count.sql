-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT
  COUNT(*) AS count
FROM blocky_authz_key AS k
JOIN blocky_authz_key_core_identifier AS ci
       ON ci.id = k.core_id
WHERE k.project_id = $1 AND
      ci.identifier = $2
