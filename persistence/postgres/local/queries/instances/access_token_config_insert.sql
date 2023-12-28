-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

INSERT INTO blocky_authz_instance_access_token_config (instance_id, favored_key_algorithm, token_lifetime)
VALUES ($1, $2, $3)

