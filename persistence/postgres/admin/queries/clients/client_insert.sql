-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

INSERT INTO blocky_authz_client (id,
                                 project_id,
                                 type,
                                 created_at,
                                 updated_at,
                                 display_name,
                                 organization_internal)
VALUES ($1, $2, $3, $4, $5, $6, $7)