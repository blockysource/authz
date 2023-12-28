-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT i.id,
       i.created_at,
       i.updated_at,
       i.display_name,
       i.project_id
FROM blocky_authz_instance AS i
