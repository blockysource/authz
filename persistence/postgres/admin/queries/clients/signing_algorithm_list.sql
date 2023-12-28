-- Copyright (c) The Blocky Source,
-- SPDX-License-Identifier: BUSL-1.1

SELECT
    csa.signing_algorithm,
    csa.priority
FROM blocky_authz_client_signing_algorithm AS csa
JOIN blocky_authz_client AS c
         ON csa.client_id = c.id
JOIN public.blocky_authz_client_identifier baci
         on c.id = baci.client_id
WHERE baci.project_id = $1
  AND baci.identifier = $2
ORDER BY csa.priority DESC