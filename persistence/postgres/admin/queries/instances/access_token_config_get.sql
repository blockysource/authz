-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT c.favored_key_algorithm,
       c.token_lifetime,
       i.project_id
FROM blocky_authz_instance_access_token_config AS c
         JOIN blocky_authz_instance AS i
              ON i.id = c.instance_id
WHERE i.project_id = $1