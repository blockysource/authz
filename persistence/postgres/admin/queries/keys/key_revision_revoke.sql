-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

UPDATE blocky_authz_key_revision AS v
SET revoked_at = $4
WHERE v.id = (SELECT vi.key_revision_id
              FROM blocky_authz_key_revision_identifier AS vi
                       JOIN blocky_authz_key_identifier AS ki ON ki.key_id = vi.key_id
              WHERE ki.project_id = $1
                AND ki.identifier = $2
                AND vi.identifier = $3)