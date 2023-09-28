-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

INSERT INTO blocky_authz_key_revision (id,
                                       key_id,
                                       project_id,
                                       created_at,
                                       priority,
                                       enc_secret,
                                       revision)
VALUES ($1, $2, $3, $4, $5, $6, $7);