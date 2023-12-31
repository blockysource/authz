-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

INSERT INTO blocky_authz_key_core (id,
                                   project_id,
                                   created_at,
                                   updated_at,
                                   display_name,
                                   algorithm,
                                   rotation_interval,
                                   priority)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
