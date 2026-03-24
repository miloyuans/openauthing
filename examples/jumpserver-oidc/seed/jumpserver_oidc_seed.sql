\set ON_ERROR_STOP on

INSERT INTO tenants (id, name, slug, status)
VALUES (
    :'tenant_id'::uuid,
    :'tenant_name',
    :'tenant_slug',
    'active'
)
ON CONFLICT (slug) DO UPDATE
SET name = EXCLUDED.name,
    status = EXCLUDED.status,
    updated_at = NOW();

INSERT INTO applications (
    id, tenant_id, name, code, type, status, homepage_url, icon_url, description
) VALUES (
    :'app_id'::uuid,
    :'tenant_id'::uuid,
    :'app_name',
    :'app_code',
    'oidc-client',
    'active',
    :'app_homepage_url',
    '',
    'JumpServer OIDC demo application'
)
ON CONFLICT (tenant_id, code) DO UPDATE
SET name = EXCLUDED.name,
    type = EXCLUDED.type,
    status = EXCLUDED.status,
    homepage_url = EXCLUDED.homepage_url,
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
    :'tenant_id'::uuid,
    :'app_id'::uuid,
    :'client_id',
    :'client_secret_hash',
    ARRAY[:'redirect_uri'],
    ARRAY[:'post_logout_redirect_uri'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['code'],
    ARRAY['openid', 'profile', 'email', 'offline_access'],
    'client_secret_basic',
    FALSE,
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
