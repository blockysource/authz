--  Copyright (c) The Blocky Source,
--  SPDX-License-Identifier: BUSL-1.1

BEGIN;


-- blocky_authz_signing_algorithm is an enumeration of supported signing algorithms.
CREATE TYPE blocky_authz_signing_algorithm AS ENUM
    ('NONE','HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA');

-- blocky_authz_instance is a table that contains instances of the service.
CREATE TABLE "blocky_authz_instance"
(
    -- id is the primary key of the table.
    id           UUID PRIMARY KEY,

    -- created_at is the time that the instance was created.
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- updated_at is the time that the instance was last updated.
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- display_name is a human readable name of the instance.
    display_name TEXT                     NOT NULL DEFAULT '',

    -- project_id is the id of the project that the instance belongs to.
    -- It is unique per project.
    project_id   TEXT UNIQUE              NOT NULL
);

-- blocky_authz_instance_config is a table that contains configurations used by the instance.
-- each entry represents a new revision of the configuration.
-- the latest configuration is used by default.
CREATE TABLE "blocky_authz_instance_config"
(
    -- id is the primary key of the table.
    id                  SERIAL PRIMARY KEY,

    -- instance_id is the id of the instance that the configuration belongs to.
    instance_id         UUID
        UNIQUE REFERENCES blocky_authz_instance (id)
        ON DELETE CASCADE,

    -- issuer is the name of the service that issues the tokens.
    -- It generally should be an url that points to the service.
    issuer              TEXT   NOT NULL,

    -- key_rotation_period is the default rotation period of the keys.
    key_rotation_period BIGINT NOT NULL DEFAULT 0
);

-- blocky_authz_instance_access_token_config is a table that contains configurations used by the access tokens.
-- the latest configuration is used by default.
CREATE TABLE "blocky_authz_instance_access_token_config"
(
    -- id is the primary key of the table.
    id                    SERIAL PRIMARY KEY,

    -- instance_id is the id of the instance that the configuration belongs to.
    instance_id           UUID
        UNIQUE REFERENCES blocky_authz_instance (id)
        ON DELETE CASCADE,

    -- favored_key_algorithm is the name of the algorithm that is favored by the service.
    favored_key_algorithm blocky_authz_signing_algorithm,

    -- is the number of seconds that the access token is valid for.
    -- if the value is 0, the access token never expires.
    token_expiration      BIGINT NOT NULL DEFAULT 0
);

-- blocky_authz_instance_refresh_token_config is a table that contains configurations used by the refresh tokens.
-- the latest configuration is used by default.
CREATE TABLE "blocky_authz_instance_refresh_token_config"
(
    -- id is the primary key of the table.
    id                    SERIAL PRIMARY KEY,

    -- instance_id is the id of the instance that the configuration belongs to.
    instance_id           UUID
        UNIQUE REFERENCES blocky_authz_instance (id)
        ON DELETE CASCADE,

    -- is the number of seconds that the refresh token is valid for.
    -- if the value is 0, the refresh token never expires.
    token_expiration      BIGINT NOT NULL DEFAULT 0,

    -- favored_key_algorithm is the name of the algorithm that is favored by the service.
    favored_key_algorithm blocky_authz_signing_algorithm,

    -- token_size is the size of the refresh token in bytes.
    -- the value is restricted to be between 16 and 2048 bytes.
    -- the default value is 128 bytes.
    token_size            SMALLINT CHECK (token_size >= 16 AND token_size <= 2048)
                                 NOT NULL DEFAULT 128
);


-- blocky_authz_key is a table that contains keys of the service.
CREATE TABLE "blocky_authz_key"
(
    -- id is the primary key of the table.
    id              UUID PRIMARY KEY                        DEFAULT gen_random_uuid(),

    -- project_id is the id of the project that the key belongs to.
    project_id      TEXT                           NOT NULL,

    -- created_at is the time that the key was created.
    created_at      TIMESTAMP WITH TIME ZONE       NOT NULL DEFAULT NOW(),

    -- updated_at is the time that the key was last updated.
    updated_at      TIMESTAMP WITH TIME ZONE       NOT NULL DEFAULT NOW(),

    -- display_name is a human readable name of the key.
    display_name    TEXT                           NOT NULL DEFAULT '',

    -- algorithm is the name of the algorithm used by the key.
    algorithm       blocky_authz_signing_algorithm NOT NULL,

    -- is the number of seconds that key revisions are valid for.
    -- after this period, the key revision is considered expired,
    -- and a service should create a new key revision.
    -- if undefined the default service configuration is used.
    -- if the value is 0, the key revision never expires.
    rotation_period BIGINT                         NOT NULL DEFAULT 0,

    -- priority is the priority of the key.
    -- the higher the priority, the more favored the key is.
    priority        INT                            NOT NULL DEFAULT 0
);

-- blocky_authz_project_id_uidx is a unique index on the project_id column of the blocky_authz_key table.
CREATE UNIQUE INDEX blocky_authz_project_id_idx ON blocky_authz_key (project_id);


-- blocky_authz_key_identifier is a table that contains identifiers of the key.
-- it is a one to many relationship with the key table (1 key can have multiple identifiers).
-- An identifier could be a string
CREATE TABLE "blocky_authz_key_identifier"
(
    -- id is the primary key of the table.
    id         SERIAL PRIMARY KEY,

    -- key_id is the id of the key that the identifier belongs to.
    key_id     UUID
        REFERENCES blocky_authz_key (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the key belongs to.
    project_id TEXT NOT NULL,

    -- identifier is the identifier of the key.
    -- it is used to identify the key inside the service.
    identifier TEXT NOT NULL,

    -- unique identifier per key.
    CONSTRAINT key_identifier_unique UNIQUE (identifier, key_id, project_id)
);


-- blocky_authz_key_identifier_key_id_idx is an index on the key_id column of the blocky_authz_key_identifier table.
CREATE INDEX blocky_authz_key_identifier_key_id_idx ON blocky_authz_key_identifier (key_id, project_id);


-- blocky_authz_key_revision is a table that contains revisions of the key.
CREATE TABLE "blocky_authz_key_revision"
(
    -- id is the primary key of the table.
    id         TEXT PRIMARY KEY,

    -- key_id is the id of the key that the revision belongs to.
    key_id     UUID REFERENCES blocky_authz_key (id)
        ON DELETE CASCADE,

    -- project_id is the id of the project that the key belongs to.
    project_id TEXT                     NOT NULL,

    -- created_at is the time that the key revision was created.
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- revoked_at is the time that the key revision was revoked.
    revoked_at TIMESTAMP WITH TIME ZONE          DEFAULT NOW(),

    -- priority is the priority of the key revision.
    -- the higher the priority, the more favored the key revision is.
    priority   INT                      NOT NULL DEFAULT 0,

    -- enc_secret is encrypted secret of the key revision.
    -- this secret is used by the service to sign and verify tokens
    enc_secret BYTEA                    NOT NULL,

    -- revision is the revision number for the key.
    revision   INT                      NOT NULL,

    -- unique revision per key.
    CONSTRAINT key_revision_unique UNIQUE (revision, key_id, project_id)
);


-- blocky_authz_key_revision_key_id_created_at_idx is an index on the key_id column of the blocky_authz_key_revision table.
CREATE INDEX blocky_authz_key_revision_key_id_created_at_idx ON blocky_authz_key_revision (key_id, created_at DESC);

-- blocky_authz_key_revision_revoked_at_idx is an index on the revoked_at column of the blocky_authz_key_revision table.
CREATE INDEX blocky_authz_key_revision_revoked_at_idx ON blocky_authz_key_revision (revoked_at);


-- blocky_authz_key_revision_identifier is a table that contains identifiers of the key revision.
-- it is a one to many relationship with the key revision table (1 key revision can have multiple identifiers).
CREATE TABLE "blocky_authz_key_revision_identifier"
(
    -- id is the primary key of the table.
    id              SERIAL PRIMARY KEY,

    -- key_revision_id is the id of the key revision that the identifier belongs to.
    key_revision_id TEXT NOT NULL
        REFERENCES blocky_authz_key_revision (id)
            ON DELETE CASCADE,

    -- key_id is the id of the key that the key revision belongs to.
    -- it is stored here for uniqueness purposes.
    key_id          UUID NOT NULL REFERENCES blocky_authz_key (id)
        ON DELETE CASCADE,

    -- identifier is the identifier of the key revision.
    -- it is used to identify the key revision inside the service.
    identifier      TEXT NOT NULL,

    -- unique key revision identifier per key.
    -- this applies also for the 'latest' key revision alias.
    CONSTRAINT key_revision_identifier_unique UNIQUE (key_id, identifier)
);


-- blocky_authz_resource_manager is a table that contains resource managers of the service.
CREATE TABLE "blocky_authz_resource_manager"
(
    -- id is the primary key of the table.
    id           UUID PRIMARY KEY                  DEFAULT gen_random_uuid(),

    -- created_at is the time that the resource manager was created.
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- updated_at is the time that the resource manager was last updated.
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- display_name is a human readable name of the resource manager.
    display_name TEXT                     NOT NULL DEFAULT '',

    -- project_id is the id of the project that the resource manager belongs to.
    -- It is unique per project.
    project_id   TEXT                     NOT NULL
);

-- blocky_authz_resource_manager_project_id_uidx is a unique index on the project_id column of the blocky_authz_resource_manager table.
CREATE UNIQUE INDEX blocky_authz_resource_manager_project_id_uidx ON blocky_authz_resource_manager (project_id);

-- blocky_authz_resource_manager_alias is a table that contains aliases of the resource manager.
CREATE TABLE "blocky_authz_resource_manager_alias"
(
    -- id is the primary key of the table.
    id                  SERIAL PRIMARY KEY,

    -- resource_manager_id is the id of the resource manager that the alias belongs to.
    resource_manager_id UUID
        REFERENCES blocky_authz_resource_manager (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the resource manager belongs to.
    project_id          TEXT NOT NULL,

    -- alias is the alias of the resource manager.
    -- it is used to identify the resource manager inside the service.
    alias               TEXT NOT NULL,

    -- unique alias per project.
    CONSTRAINT resource_manager_alias_unique UNIQUE (alias, project_id)
);

-- blocky_authz_resource_manager_alias_resource_manager_id_idx is an index on the resource_manager_id column of the blocky_authz_resource_manager_alias table.
CREATE INDEX blocky_authz_resource_manager_alias_resource_manager_id_idx ON blocky_authz_resource_manager_alias (resource_manager_id, project_id);


-- blocky_authz_resource_manager_identifier is a table that contains identifiers of the resource manager.
-- it is a one to many relationship with the resource manager table (1 resource manager can have multiple identifiers).
CREATE TABLE "blocky_authz_resource_manager_identifier"
(
    -- id is the primary key of the table.
    id                  SERIAL PRIMARY KEY,

    -- resource_manager_id is the id of the resource manager that the identifier belongs to.
    resource_manager_id UUID
        REFERENCES blocky_authz_resource_manager (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the resource manager belongs to.
    project_id          TEXT NOT NULL,

    -- identifier is the identifier of the resource manager.
    -- it is used to identify the resource manager inside the service.
    identifier          TEXT NOT NULL,

    -- unique identifier per project.
    CONSTRAINT resource_manager_identifier_unique UNIQUE (identifier, project_id)
);

-- blocky_authz_resource_manager_identifier_resource_mgr_id_idx is an index on the resource_manager_id column of the blocky_authz_resource_manager_identifier table.
CREATE INDEX blocky_authz_resource_manager_identifier_resource_mgr_id_idx ON blocky_authz_resource_manager_identifier (resource_manager_id, project_id);


-- blocky_authz_resource_permission is a table that contains permissions of the resource.
CREATE TABLE "blocky_authz_resource_permission"
(
    -- id is the primary key of the table.
    id                  UUID PRIMARY KEY                  DEFAULT gen_random_uuid(),

    -- resource_manager_id is the id of the resource that the permission belongs to.
    resource_manager_id UUID
        REFERENCES blocky_authz_resource_manager (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the resource belongs to.
    project_id          TEXT                     NOT NULL,

    -- uid is a unique UUID that identifies the resource.
    uid                 UUID UNIQUE              NOT NULL DEFAULT gen_random_uuid(),

    -- scope is the permission of the resource.
    -- it is used to identify the resource inside the service.
    scope               TEXT                     NOT NULL,

    -- created_at is the time that the permission was created.
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- updated_at is the time that the permission was last updated.
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- display_name is a human readable name of the permission.
    display_name        TEXT                     NOT NULL DEFAULT '',

    -- description is a human readable description of the permission.
    description         TEXT                     NOT NULL DEFAULT '',

    -- unique scope per project.
    CONSTRAINT resource_permission_scope_unique UNIQUE (scope, project_id)
);


-- blocky_authz_resource_permission_identifier is a table that contains identifiers of the resource permission.
-- it is a one to many relationship with the resource permission table (1 resource permission can have multiple identifiers).
CREATE TABLE "blocky_authz_resource_permission_identifier"
(
    -- id is the primary key of the table.
    id                     SERIAL PRIMARY KEY,

    -- resource_permission_id is the id of the resource permission that the identifier belongs to.
    resource_permission_id UUID
        REFERENCES blocky_authz_resource_permission (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the resource permission belongs to.
    project_id             TEXT NOT NULL,

    -- identifier is the identifier of the resource permission.
    -- it is used to identify the resource permission inside the service.
    identifier             TEXT NOT NULL,

    -- unique identifier per project.
    CONSTRAINT resource_permission_identifier_unique UNIQUE (identifier, project_id)
);

-- blocky_authz_resource_permission_identifier_permission_id_idx is an index on the resource_permission_id column of the blocky_authz_resource_permission_identifier table.
CREATE INDEX blocky_authz_resource_permission_identifier_permission_id_idx ON blocky_authz_resource_permission_identifier (resource_permission_id, project_id);

-- blocky_authz_resource_permission_alias is a table that contains aliases of the resource permission.
CREATE TABLE "blocky_authz_resource_permission_alias"
(
    -- id is the primary key of the table.
    id                     SERIAL PRIMARY KEY,

    -- resource_permission_id is the id of the resource permission that the alias belongs to.
    resource_permission_id UUID
        REFERENCES blocky_authz_resource_permission (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the resource permission belongs to.
    project_id             TEXT NOT NULL,

    -- alias is the alias of the resource permission.
    -- it is used to identify the resource permission inside the service.
    alias                  TEXT NOT NULL,

    -- unique alias per project.
    CONSTRAINT resource_permission_alias_unique UNIQUE (alias, project_id)
);

-- blocky_authz_resource_permission_alias_permission_id_idx is an index on the resource_permission_id column of the blocky_authz_resource_permission_alias table.
CREATE INDEX blocky_authz_resource_permission_alias_permission_id_idx ON blocky_authz_resource_permission_alias (resource_permission_id, project_id);


-- blocky_authz_client is a table that contains clients of the service.
CREATE TABLE "blocky_authz_client"
(
    -- id is the primary key of the table.
    id           TEXT PRIMARY KEY,

    -- project_id is the id of the project that the client belongs to.
    project_id   TEXT                     NOT NULL,

    -- created_at is the time that the client was created.
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- updated_at is the time that the client was last updated.
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- display_name is a human readable name of the client.
    display_name TEXT                     NOT NULL DEFAULT ''
);

-- blocky_authz_client_project_id_idx is an index on the project_id column of the blocky_authz_client table.
CREATE INDEX blocky_authz_client_project_id_idx ON blocky_authz_client (project_id);


-- blocky_authz_client_alias is a table that contains aliases of the client.
CREATE TABLE "blocky_authz_client_alias"
(
    -- id is the primary key of the table.
    id         SERIAL PRIMARY KEY,

    -- client_id is the id of the client that the alias belongs to.
    client_id  TEXT
        REFERENCES blocky_authz_client (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the client belongs to.
    project_id TEXT NOT NULL,

    -- alias is the alias of the client.
    -- it is used to identify the client inside the service.
    alias      TEXT NOT NULL,

    -- unique alias per project.
    CONSTRAINT client_alias_unique UNIQUE (alias, project_id)
);


-- blocky_authz_client_alias_client_id_idx is an index on the client_id column of the blocky_authz_client_alias table.
CREATE INDEX blocky_authz_client_alias_client_id_idx ON blocky_authz_client_alias (client_id, project_id);

-- blocky_authz_client_signing_algorithm is a table that contains the algorithms supported by the client.
-- it is a one to many relationship with the client table (1 client can have multiple algorithms).
CREATE TABLE "blocky_authz_client_signing_algorithm"
(
    -- id is the primary key of the table.
    id                SERIAL PRIMARY KEY,

    -- client_id is the id of the client that the algorithm belongs to.
    client_id         TEXT                           NOT NULL
        REFERENCES blocky_authz_client (id)
            ON DELETE CASCADE,

    -- signing_algorithm is the name of the signing algorithm.
    -- it needs to be unique per client.
    signing_algorithm blocky_authz_signing_algorithm NOT NULL,

    -- priority is the order of the algorithm in the array of algorithms.
    priority          INT                            NOT NULL,

    -- unique algorithm per client.
    CONSTRAINT client_algorithm_unique UNIQUE (client_id, signing_algorithm),

    -- unique priority per client.
    CONSTRAINT client_algorithm_priority_unique UNIQUE (client_id, priority)
);

-- blocky_authz_client_identifier is a table that contains identifiers of the client.
-- it is a one to many relationship with the client table (1 client can have multiple identifiers).
CREATE TABLE "blocky_authz_client_identifier"
(
    -- id is the primary key of the table.
    id         SERIAL PRIMARY KEY,

    -- client_id is the id of the client that the identifier belongs to.
    client_id  TEXT
        REFERENCES blocky_authz_client (id)
            ON DELETE CASCADE,

    -- project_id is the id of the project that the client belongs to.
    project_id TEXT NOT NULL,

    -- identifier is the identifier of the client.
    -- it is used to identify the client inside the service.
    identifier TEXT NOT NULL,

    CONSTRAINT client_identifier_unique UNIQUE (identifier, project_id)
);

-- blocky_authz_client_identifier_client_id_idx is an index on the client_id column of the blocky_authz_client_identifier table.
CREATE INDEX blocky_authz_client_identifier_client_id_idx ON blocky_authz_client_identifier (client_id, project_id);


-- blocky_authz_client_credentials is a table that contains credentials of the client.
CREATE TABLE "blocky_authz_client_credentials"
(
    -- id is the primary key of the table.
    id          SERIAL PRIMARY KEY,

    -- client_id is the id of the client that the credentials belongs to.
    client_id   TEXT
        REFERENCES blocky_authz_client (id)
            ON DELETE CASCADE,


    -- secret is the secret of the client.
    -- it is used to authenticate the client.
    secret      BYTEA                    NOT NULL,

    -- secret_hash is the hash of the secret.
    -- it is used to authenticate the client.
    secret_hash BYTEA                    NOT NULL,

    -- created_at is the time that the credentials were created.
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- blocky_authz_client_credentials_client_id_idx is an index on the client_id column of the blocky_authz_client_credentials table.
CREATE INDEX blocky_authz_client_credentials_client_id_idx ON blocky_authz_client_credentials (client_id);


COMMIT;