-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

DELETE
FROM blocky_authz_key_core_identifier
WHERE identifier = $1 AND
      core_id = $2
