SELECT
    reltuples AS estimated_rows
FROM pg_class
WHERE relname = 'blocky_authz_key'
