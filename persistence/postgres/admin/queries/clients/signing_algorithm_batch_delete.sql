-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

  WITH context_clients AS (SELECT c.id
                             FROM blocky_authz_client AS c
                                      JOIN public.blocky_authz_client_identifier baci
                                      ON c.id = baci.client_id
                            WHERE c.project_id = $1
                              AND baci.identifier = $2)
DELETE
  FROM blocky_authz_client_signing_algorithm USING context_clients
 WHERE client_id = context_clients.id