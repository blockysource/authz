-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT
    c.id                 AS id,
    c.project_id         AS project_id,
    c.created_at         AS created_at,
    c.updated_at         AS updated_at,
    c.display_name       AS display_name,
    c.algorithm          AS algorithm,
    c.rotation_interval  AS rotation_interval,
    c.priority           AS priority,
    v.derived_keys_count AS derived_keys_count,
    r.last_rotation      AS last_rotation
  FROM blocky_authz_key_core AS c
           LEFT JOIN LATERAL ( SELECT COUNT(*) AS derived_keys_count
                                 FROM blocky_authz_key AS k
                                WHERE k.core_id = c.id ) AS v
           ON TRUE
           LEFT JOIN LATERAL ( SELECT MAX(k.created_at) AS last_rotation
                                 FROM blocky_authz_key AS k
                                WHERE k.core_id = c.id ) AS r
           ON TRUE
 WHERE c.project_id = $1