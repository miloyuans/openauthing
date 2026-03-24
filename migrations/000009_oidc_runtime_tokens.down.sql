DROP INDEX IF EXISTS oidc_refresh_tokens_session_idx;

ALTER TABLE oidc_refresh_tokens
    DROP COLUMN IF EXISTS reuse_detected_at,
    DROP COLUMN IF EXISTS replaced_by_id,
    DROP COLUMN IF EXISTS rotated_at,
    DROP COLUMN IF EXISTS client_id;

DROP INDEX IF EXISTS oidc_access_tokens_client_user_idx;
DROP INDEX IF EXISTS oidc_access_tokens_session_idx;
DROP TABLE IF EXISTS oidc_access_tokens;
