INSERT INTO tenants (id, name, slug, status)
VALUES (
    '10000000-0000-0000-0000-000000000001',
    'Local Dev Tenant',
    'local-dev',
    'active'
)
ON CONFLICT (slug) DO UPDATE
SET name = EXCLUDED.name,
    status = EXCLUDED.status,
    updated_at = NOW();

INSERT INTO applications (
    id, tenant_id, name, code, type, status, homepage_url, icon_url, description
) VALUES (
    '20000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000001',
    'OIDC PKCE Demo',
    'oidc-pkce-demo',
    'oidc-client',
    'active',
    'http://localhost:5173/callback',
    '',
    'Local development public OIDC client'
)
ON CONFLICT (tenant_id, code) DO UPDATE
SET name = EXCLUDED.name,
    status = EXCLUDED.status,
    homepage_url = EXCLUDED.homepage_url,
    icon_url = EXCLUDED.icon_url,
    description = EXCLUDED.description,
    updated_at = NOW();

INSERT INTO oidc_clients (
    tenant_id,
    app_id,
    client_id,
    client_secret_hash,
    redirect_uris,
    post_logout_redirect_uris,
    grant_types,
    response_types,
    scopes,
    token_endpoint_auth_method,
    require_pkce,
    access_token_ttl,
    refresh_token_ttl,
    id_token_signed_response_alg
) VALUES (
    '10000000-0000-0000-0000-000000000001',
    '20000000-0000-0000-0000-000000000001',
    'openauthing-demo-public',
    NULL,
    ARRAY['http://localhost:5173/callback'],
    ARRAY['http://localhost:5173/logout-callback'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['code'],
    ARRAY['openid', 'profile', 'email', 'offline_access'],
    'none',
    TRUE,
    600,
    3600,
    'RS256'
)
ON CONFLICT (client_id) DO UPDATE
SET tenant_id = EXCLUDED.tenant_id,
    app_id = EXCLUDED.app_id,
    client_secret_hash = EXCLUDED.client_secret_hash,
    redirect_uris = EXCLUDED.redirect_uris,
    post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
    grant_types = EXCLUDED.grant_types,
    response_types = EXCLUDED.response_types,
    scopes = EXCLUDED.scopes,
    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
    require_pkce = EXCLUDED.require_pkce,
    access_token_ttl = EXCLUDED.access_token_ttl,
    refresh_token_ttl = EXCLUDED.refresh_token_ttl,
    id_token_signed_response_alg = EXCLUDED.id_token_signed_response_alg,
    updated_at = NOW();
