-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

UPDATE blocky_authz_key_revision_identifier AS vi
SET key_revision_id = $2
WHERE vi.key_id = $1
  AND vi.identifier = 'latest'