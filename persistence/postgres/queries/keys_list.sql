SELECT k.id              AS id,
       k.sid             AS sid,
       k.created_at      AS created_at,
       k.display_name    AS display_name,
       k.rotation_period AS rotation_period,
       k.priority        AS priority,
       k.versions        AS versions,
       k.active          AS active,
       ka.algorithms     AS algorithms
FROM blocky_authz_key AS k
         LEFT JOIN LATERAL (
    SELECT array_agg(ka.signing_algorithm) AS algorithms
    FROM blocky_authz_key_algorithm AS ka
    WHERE ka.key_id = k.id
    ) AS ka ON TRUE