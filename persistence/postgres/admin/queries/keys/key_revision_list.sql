-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT v.id         AS id,
       v.key_id     AS key_id,
       v.project_id AS project_id,
       v.created_at AS created_at,
       v.revoked_at AS revoked_at,
       v.priority   AS priority,
       v.enc_secret AS enc_secret,
       v.revision   AS revision
FROM blocky_authz_key_revision v
         JOIN blocky_authz_key_identifier ki ON ki.key_id = v.key_id
WHERE ki.project_id = $1
  AND ki.identifier = $2