-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT
    c.id                    AS id,
    c.project_id            AS project_id,
    c.type                  AS type,
    c.created_at            AS created_at,
    c.updated_at            AS updated_at,
    c.display_name          AS display_name,
    c.organization_internal AS organization_internal
FROM blocky_authz_client AS c
JOIN blocky_authz_client_identifier AS i
         ON c.id = i.client_id
WHERE i.project_id = $1
  AND i.identifier = $2