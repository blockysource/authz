-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT r.id         AS revision_id,
       k.id         AS key_id,
       k.project_id AS project_id,
       k.algorithm  AS algorithm,
       k.priority   AS priority,
       r.enc_secret AS enc_secret,
       r.revision   AS revision
FROM blocky_authz_key_revision AS r
         JOIN blocky_authz_key AS k ON k.id = r.key_id
WHERE r.revoked_at IS NULL
  AND k.project_id = $1
ORDER BY k.priority DESC, k.id, r.revision DESC
