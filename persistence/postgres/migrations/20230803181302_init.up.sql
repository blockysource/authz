BEGIN;

-- blocky_authz_signing_algorithm is an enumeration of supported signing algorithms.
CREATE TYPE blocky_authz_signing_algorithm AS ENUM
    ('NONE','HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA');


CREATE TABLE "blocky_authz_key"
(
    -- id is the primary key of the table.
    id              SERIAL PRIMARY KEY,

    -- sid is a string that uniquely identifies the key.
    -- it is used to identify the key outside of the service.
    sid             TEXT UNIQUE              NOT NULL,

    -- created_at is the time that the key was created.
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- display_name is a human readable name of the key.
    display_name    TEXT                     NOT NULL DEFAULT '',

    -- active is a flag that indicates whether the key is active or not.
    -- if the key is not active, it is not used for signing.
    active          BOOLEAN                  NOT NULL DEFAULT false,

    -- last_rotated_at is the time that the key was last rotated.
    last_rotated_at TIMESTAMP WITH TIME ZONE          DEFAULT NOW(),


    -- is the number of seconds that key versions are valid for.
    -- after this period, the key version is considered expired,
    -- and a service should create a new key version.
    -- if undefined the default service configuration is used.
    -- if the value is 0, the key version never expires.
    rotation_period BIGINT                   NOT NULL DEFAULT 0,

    -- priority is the priority of the key.
    -- the higher the priority, the more favored the key is.
    priority        INT                      NOT NULL DEFAULT 0,

    -- versions is the number of versions belonging to the key.
    versions        INT                      NOT NULL DEFAULT 0
);

-- blocky_authz_key_algorithm is a table that contains the algorithms supported by the key.
-- it is a one to many relationship with the key table (1 key can have multiple algorithms).
CREATE TABLE "blocky_authz_key_algorithm"
(
    -- id is the primary key of the table.
    id                SERIAL PRIMARY KEY,

    -- key_id is the id of the key that the algorithm belongs to.
    key_id            INT                            NOT NULL
        REFERENCES blocky_authz_key (id)
            ON DELETE CASCADE,

    -- signing_algorithm is the name of the signing algorithm.
    -- it needs to be unique per key.
    signing_algorithm blocky_authz_signing_algorithm NOT NULL,

    CONSTRAINT key_algorithm_unique UNIQUE (key_id, signing_algorithm)
);

-- blocky_authz_key_algorithm_key_id_idx is an index on the key_id column of the blocky_authz_key_algorithm table.
CREATE INDEX blocky_authz_key_algorithm_key_id_idx ON blocky_authz_key_algorithm (key_id);


-- blocky_authz_service_config is a table that contains configurations used by the service.
-- each entry represents a new version of the configuration.
-- the latest configuration is used by default.
CREATE TABLE "blocky_authz_service_config"
(
    id                  SERIAL PRIMARY KEY,
    -- the creation time of the record.
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- issuer is the name of the service that issues the tokens.
    -- It generally should be an url that points to the service.
    issuer              TEXT                     NOT NULL,

    -- is the identifier of the default key served by the service.
    -- this is the lowest level of the key hierarchy.
    default_key_id      INT
        REFERENCES blocky_authz_key (id)
            ON DELETE RESTRICT,

    -- key_rotation_period is the default rotation period of the keys.
    key_rotation_period BIGINT                   NOT NULL DEFAULT 0
);

-- access_token_config is a table that contains configurations used by the access tokens.
-- the latest configuration is used by default.
CREATE TABLE IF NOT EXISTS "blocky_authz_access_token_config"
(
    -- id is the primary key of the table.
    id                    SERIAL PRIMARY KEY,

    -- created_at is the time that the configuration was created.
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- favored_key_algorithm is the name of the algorithm that is favored by the service.
    favored_key_algorithm blocky_authz_signing_algorithm,

    -- is the number of seconds that the access token is valid for.
    -- if the value is 0, the access token never expires.
    token_expiration      BIGINT                   NOT NULL,


    -- is the default key identifier used for signing the access tokens.
    -- this is one level hierarchically above the default key of the service.
    default_key_id        INT
        REFERENCES blocky_authz_key (id)
            ON DELETE RESTRICT
);


-- blocky_authz_refresh_token_config is a table that contains configurations used by the refresh tokens.
-- the latest configuration is used by default.
CREATE TABLE blocky_authz_refresh_token_config
(
    -- id is the primary key of the table.
    id                    SERIAL PRIMARY KEY,

    -- created_at is the time that the configuration was created.
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- is the number of seconds that the refresh token is valid for.
    -- if the value is 0, the refresh token never expires.
    -- It is not recommended to set this value to 0.
    token_expiration      BIGINT                   NOT NULL,

    -- favored_key_algorithm is the name of the algorithm that is favored by the service.
    favored_key_algorithm blocky_authz_signing_algorithm,

    -- token_size is the size of the refresh token in bytes.
    -- the value is restricted to be between 16 and 2048 bytes.
    -- the default value is 128 bytes.
    token_size            SMALLINT CHECK (token_size >= 16 AND token_size <= 2048)
                                                   NOT NULL DEFAULT 128
);

COMMIT;