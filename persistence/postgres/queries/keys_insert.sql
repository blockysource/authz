INSERT INTO blocky_authz_key
    (sid, created_at, display_name, active, rotation_period, priority)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id;