-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT ki.key_id     AS key_id,
       ki.project_id AS project_id,
       ki.identifier AS identifier
FROM blocky_authz_key_identifier AS ki
WHERE ki.identifier = $1
  AND ki.project_id = $2