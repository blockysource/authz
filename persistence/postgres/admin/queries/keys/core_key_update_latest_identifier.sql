-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

UPDATE blocky_authz_key_core_key_identifier AS cki
SET key_id = $2
WHERE cki.core_id = $1 AND
      cki.identifier = 'latest'