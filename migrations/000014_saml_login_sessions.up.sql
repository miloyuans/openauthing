CREATE TABLE saml_login_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    name_id VARCHAR(512) NOT NULL,
    session_index VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    logout_at TIMESTAMPTZ NULL,
    CONSTRAINT saml_login_sessions_app_session_uidx UNIQUE (app_id, session_id)
);

CREATE INDEX saml_login_sessions_app_session_index_idx ON saml_login_sessions (app_id, session_index, status);
CREATE INDEX saml_login_sessions_app_name_id_idx ON saml_login_sessions (app_id, name_id, status);
CREATE INDEX saml_login_sessions_session_id_idx ON saml_login_sessions (session_id, status);
