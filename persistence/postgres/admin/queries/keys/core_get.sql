-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT
  c.id                  AS id,
  c.project_id          AS project_id,
  c.created_at          AS created_at,
  c.updated_at          AS updated_at,
  c.display_name        AS display_name,
  c.algorithm           AS algorithm,
  c.rotation_interval   AS rotation_interval,
  c.priority            AS priority,
  dk.derived_keys_count AS derived_keys_count,
  kr.created_at         AS last_rotation
FROM blocky_authz_key_core AS c
LEFT JOIN blocky_authz_key_core_identifier AS i
            ON i.core_id = c.id
LEFT JOIN LATERAL (
            SELECT
              COUNT(*) AS derived_keys_count
            FROM blocky_authz_key AS k
            WHERE k.core_id = c.id
            ) as dk
            ON true
LEFT JOIN LATERAL (
            SELECT
              MAX(k.created_at) AS created_at
            FROM blocky_authz_key AS k
            WHERE k.core_id = c.id
            ) AS kr
            ON true
WHERE i.identifier = $1 AND
      i.project_id = $2
