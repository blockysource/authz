-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT
  COUNT(*)
FROM blocky_authz_key_core
WHERE project_id = $1