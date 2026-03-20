CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sid VARCHAR(64) NOT NULL,
    login_method VARCHAR(32) NOT NULL,
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ip VARCHAR(64) NOT NULL DEFAULT '',
    user_agent VARCHAR(512) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logout_at TIMESTAMPTZ,
    CONSTRAINT auth_sessions_status_check CHECK (status IN ('active', 'logged_out', 'revoked')),
    CONSTRAINT auth_sessions_login_method_check CHECK (login_method IN ('username', 'email'))
);

CREATE UNIQUE INDEX auth_sessions_sid_uidx ON auth_sessions (sid);
CREATE INDEX auth_sessions_user_id_created_at_idx ON auth_sessions (user_id, created_at DESC);
CREATE INDEX auth_sessions_tenant_id_user_id_status_idx ON auth_sessions (tenant_id, user_id, status);
