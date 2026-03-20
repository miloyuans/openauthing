DROP INDEX IF EXISTS oidc_refresh_tokens_client_user_created_at_idx;
DROP TABLE IF EXISTS oidc_refresh_tokens;

DROP INDEX IF EXISTS oidc_authorization_codes_user_session_idx;
DROP INDEX IF EXISTS oidc_authorization_codes_client_created_at_idx;
DROP TABLE IF EXISTS oidc_authorization_codes;

DROP INDEX IF EXISTS oidc_clients_app_id_idx;
DROP INDEX IF EXISTS oidc_clients_tenant_id_idx;
DROP TABLE IF EXISTS oidc_clients;
