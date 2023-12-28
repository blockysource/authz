-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

INSERT INTO blocky_authz_instance_refresh_token_config (instance_id, token_lifetime, favored_key_algorithm, token_size)
VALUES ($1, $2, $3, $4)