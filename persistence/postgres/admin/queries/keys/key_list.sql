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
       v.versions        AS versions,
       r.last_rotation   AS last_rotation
FROM blocky_authz_key AS k
         LEFT JOIN LATERAL (
    SELECT COUNT(*) AS versions
    FROM blocky_authz_key_version AS v
    WHERE v.key_id = k.id
    ) AS v ON TRUE
         LEFT JOIN LATERAL (
    SELECT MAX(v.created_at) AS last_rotation
    FROM blocky_authz_key_version AS v
    WHERE v.key_id = k.id
    ) AS r ON TRUE
WHERE k.project_id = $1