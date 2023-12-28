-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT i.created_at   AS created_at,
       i.updated_at   AS updated_at,
       i.display_name AS display_name,
       i.project_id   AS project_id
FROM blocky_authz_instance AS i
WHERE i.project_id = $1