--  Copyright (c) The Blocky Source,
--  SPDX-License-Identifier: BUSL-1.1

BEGIN;

DROP TABLE "blocky_authz_client_resource_permissions";
DROP TABLE "blocky_authz_client_credentials";
DROP TABLE "blocky_authz_client_identifier";
DROP TABLE "blocky_authz_client_signing_algorithm";
DROP TABLE "blocky_authz_client_alias";
DROP TABLE "blocky_authz_client";
DROP TABLE "blocky_authz_resource_permission_alias";
DROP TABLE "blocky_authz_resource_permission_identifier";
DROP TABLE "blocky_authz_resource_permission";
DROP TABLE "blocky_authz_resource_manager_identifier";
DROP TABLE "blocky_authz_resource_manager_alias";
DROP TABLE "blocky_authz_resource_manager";
DROP TABLE "blocky_authz_key_core_key_identifier";
DROP TABLE "blocky_authz_key";
DROP TABLE "blocky_authz_key_core_identifier";
DROP TABLE "blocky_authz_key_core";
DROP TABLE "blocky_authz_instance_refresh_token_config";
DROP TABLE "blocky_authz_instance_access_token_config";
DROP TABLE "blocky_authz_instance_config";
DROP TABLE "blocky_authz_instance";
DROP TYPE blocky_authz_signing_algorithm;

COMMIT;
