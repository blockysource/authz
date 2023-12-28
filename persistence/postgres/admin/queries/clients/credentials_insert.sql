-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

INSERT INTO blocky_authz_client_credentials (client_id, secret_hash, created_at)
VALUES ($1, $2, $3)