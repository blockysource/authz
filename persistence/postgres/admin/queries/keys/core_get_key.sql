-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT
    k.id         AS id,
    k.core_id    AS core_id,
    k.project_id AS project_id,
    k.created_at AS created_at,
    k.revoked_at AS revoked_at,
    k.priority   AS priority,
    k.revision   AS revision
FROM blocky_authz_key k
JOIN blocky_authz_key_core_identifier AS ci
         ON ci.core_id = k.core_id
JOIN blocky_authz_key_core_key_identifier AS cki
         ON cki.key_id = k.id
WHERE k.project_id = $1
  AND ci.identifier = $2
  AND cki.identifier = $3