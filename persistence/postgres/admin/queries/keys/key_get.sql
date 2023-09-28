-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT k.id              AS id,
       k.project_id      AS project_id,
       k.created_at      AS created_at,
       k.updated_at      AS updated_at,
       k.display_name    AS display_name,
       k.algorithm       AS algorithm,
       k.rotation_period AS rotation_period,
       k.priority        AS priority,
       v.revisions        AS revisions,
       vi.created_at     AS last_rotation
FROM blocky_authz_key AS k
         LEFT JOIN blocky_authz_key_identifier AS i ON i.key_id = k.id
         LEFT JOIN LATERAL (
    SELECT COUNT(*) AS revisions
    FROM blocky_authz_key_revision AS v
    WHERE v.key_id = k.id
    ) as v ON true
         LEFT JOIN LATERAL (
    SELECT MAX(vi.created_at) AS created_at
    FROM blocky_authz_key_revision AS vi
    WHERE vi.key_id = k.id
    ) AS vi ON true
WHERE i.identifier = $1
  AND i.project_id = $2
