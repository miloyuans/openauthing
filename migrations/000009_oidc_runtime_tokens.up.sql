CREATE TABLE oidc_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    client_id VARCHAR(128) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    CONSTRAINT oidc_access_tokens_token_hash_uidx UNIQUE (token_hash)
);

CREATE INDEX oidc_access_tokens_session_idx
    ON oidc_access_tokens (session_id, created_at DESC);
CREATE INDEX oidc_access_tokens_client_user_idx
    ON oidc_access_tokens (oidc_client_id, user_id, created_at DESC);

ALTER TABLE oidc_refresh_tokens
    ADD COLUMN client_id VARCHAR(128);

UPDATE oidc_refresh_tokens rt
SET client_id = oc.client_id
FROM oidc_clients oc
WHERE oc.id = rt.oidc_client_id
  AND rt.client_id IS NULL;

ALTER TABLE oidc_refresh_tokens
    ALTER COLUMN client_id SET NOT NULL;

ALTER TABLE oidc_refresh_tokens
    ADD COLUMN rotated_at TIMESTAMPTZ,
    ADD COLUMN replaced_by_id UUID REFERENCES oidc_refresh_tokens(id) ON DELETE SET NULL,
    ADD COLUMN reuse_detected_at TIMESTAMPTZ;

CREATE INDEX oidc_refresh_tokens_session_idx
    ON oidc_refresh_tokens (session_id, created_at DESC);
