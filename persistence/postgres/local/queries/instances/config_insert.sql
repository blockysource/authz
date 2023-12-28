-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

INSERT INTO blocky_authz_instance_config (instance_id, issuer, key_rotation_period)
VALUES ($1, $2, $3)