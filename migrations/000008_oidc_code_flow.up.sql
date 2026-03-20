CREATE TABLE oidc_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    client_id VARCHAR(128) NOT NULL,
    client_secret_hash VARCHAR(255),
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL,
    response_types TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL,
    token_endpoint_auth_method VARCHAR(32) NOT NULL DEFAULT 'client_secret_basic',
    require_pkce BOOLEAN NOT NULL DEFAULT FALSE,
    access_token_ttl INTEGER NOT NULL,
    refresh_token_ttl INTEGER NOT NULL,
    id_token_signed_response_alg VARCHAR(16) NOT NULL DEFAULT 'RS256',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oidc_clients_client_id_uidx UNIQUE (client_id),
    CONSTRAINT oidc_clients_token_endpoint_auth_method_check CHECK (
        token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none')
    ),
    CONSTRAINT oidc_clients_access_token_ttl_check CHECK (access_token_ttl > 0),
    CONSTRAINT oidc_clients_refresh_token_ttl_check CHECK (refresh_token_ttl > 0),
    CONSTRAINT oidc_clients_id_token_alg_check CHECK (id_token_signed_response_alg IN ('RS256'))
);

CREATE INDEX oidc_clients_tenant_id_idx ON oidc_clients (tenant_id);
CREATE INDEX oidc_clients_app_id_idx ON oidc_clients (app_id);

CREATE TABLE oidc_authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    redirect_uri VARCHAR(2048) NOT NULL,
    scopes TEXT[] NOT NULL,
    nonce VARCHAR(255) NOT NULL DEFAULT '',
    code_challenge VARCHAR(255) NOT NULL DEFAULT '',
    code_challenge_method VARCHAR(32) NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ,
    CONSTRAINT oidc_authorization_codes_code_hash_uidx UNIQUE (code_hash),
    CONSTRAINT oidc_authorization_codes_code_challenge_method_check CHECK (
        code_challenge_method IN ('', 'S256')
    )
);

CREATE INDEX oidc_authorization_codes_client_created_at_idx
    ON oidc_authorization_codes (oidc_client_id, created_at DESC);
CREATE INDEX oidc_authorization_codes_user_session_idx
    ON oidc_authorization_codes (user_id, session_id);

CREATE TABLE oidc_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    CONSTRAINT oidc_refresh_tokens_token_hash_uidx UNIQUE (token_hash)
);

CREATE INDEX oidc_refresh_tokens_client_user_created_at_idx
    ON oidc_refresh_tokens (oidc_client_id, user_id, created_at DESC);
