BEGIN;

INSERT INTO blocky_authz_key
    (id, sid, created_at, display_name, active, rotation_period, priority, versions)
VALUES (1, '1', NOW(), 'test 1', false, 0, 0, 0)

INSERT INTO blocky_authz_key_algorithm
 (key_id, signing_algorithm)
VALUES (1, 'RS256'), (1, 'RS384'), (1, 'RS512'), (1, 'ES256'), (1, 'ES384'), (1, 'ES512'), (1, 'PS256'), (1, 'PS384'), (1, 'PS512')

COMMIT;