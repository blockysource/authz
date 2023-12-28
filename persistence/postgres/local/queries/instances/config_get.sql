-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT c.issuer              AS issuer,
       c.key_rotation_period AS key_rotation_period
FROM blocky_authz_instance_config AS c
WHERE c.instance_id = $1