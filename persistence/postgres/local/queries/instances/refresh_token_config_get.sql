-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT c.instance_id           AS instance_id,
       c.token_lifetime        AS token_lifetime,
       c.favored_key_algorithm AS favored_key_algorithm,
       c.token_size            AS token_size
FROM blocky_authz_instance_refresh_token_config AS c
WHERE c.instance_id = $1
