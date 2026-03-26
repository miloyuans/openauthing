param(
    [string]$PostgresService = "postgres",
    [string]$PostgresUser = "openauthing",
    [string]$VerifyDatabase = "openauthing_verify"
)

$ErrorActionPreference = "Stop"

function Invoke-Compose {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    & docker compose @Args
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed: $($Args -join ' ')"
    }
}

function Invoke-Psql {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Database,
        [Parameter(Mandatory = $true)]
        [string]$Sql
    )

    $Sql | & docker compose exec -T $PostgresService psql -v ON_ERROR_STOP=1 -U $PostgresUser -d $Database
    if ($LASTEXITCODE -ne 0) {
        throw "psql failed against database $Database"
    }
}

Invoke-Compose -Args @("up", "-d", $PostgresService)
Invoke-Compose -Args @("exec", "-T", $PostgresService, "psql", "-v", "ON_ERROR_STOP=1", "-U", $PostgresUser, "-d", "postgres", "-c", "DROP DATABASE IF EXISTS $VerifyDatabase WITH (FORCE);")
Invoke-Compose -Args @("exec", "-T", $PostgresService, "psql", "-v", "ON_ERROR_STOP=1", "-U", $PostgresUser, "-d", "postgres", "-c", "CREATE DATABASE $VerifyDatabase;")

$applyUp = "for file in /migrations/*.up.sql; do psql -v ON_ERROR_STOP=1 -U $PostgresUser -d $VerifyDatabase -f `$file; done"
Invoke-Compose -Args @("exec", "-T", $PostgresService, "sh", "-lc", $applyUp)

$verifyUp = @'
DO $$
BEGIN
    IF to_regclass('public.tenants') IS NULL THEN
        RAISE EXCEPTION 'missing table: tenants';
    END IF;
    IF to_regclass('public.users') IS NULL THEN
        RAISE EXCEPTION 'missing table: users';
    END IF;
    IF to_regclass('public.user_profiles') IS NULL THEN
        RAISE EXCEPTION 'missing table: user_profiles';
    END IF;
    IF to_regclass('public.groups') IS NULL THEN
        RAISE EXCEPTION 'missing table: groups';
    END IF;
    IF to_regclass('public.user_groups') IS NULL THEN
        RAISE EXCEPTION 'missing table: user_groups';
    END IF;
    IF to_regclass('public.roles') IS NULL THEN
        RAISE EXCEPTION 'missing table: roles';
    END IF;
    IF to_regclass('public.permissions') IS NULL THEN
        RAISE EXCEPTION 'missing table: permissions';
    END IF;
    IF to_regclass('public.role_permissions') IS NULL THEN
        RAISE EXCEPTION 'missing table: role_permissions';
    END IF;
    IF to_regclass('public.user_roles') IS NULL THEN
        RAISE EXCEPTION 'missing table: user_roles';
    END IF;
    IF to_regclass('public.applications') IS NULL THEN
        RAISE EXCEPTION 'missing table: applications';
    END IF;
    IF to_regclass('public.auth_sessions') IS NULL THEN
        RAISE EXCEPTION 'missing table: auth_sessions';
    END IF;
    IF to_regclass('public.oidc_clients') IS NULL THEN
        RAISE EXCEPTION 'missing table: oidc_clients';
    END IF;
    IF to_regclass('public.oidc_authorization_codes') IS NULL THEN
        RAISE EXCEPTION 'missing table: oidc_authorization_codes';
    END IF;
    IF to_regclass('public.oidc_refresh_tokens') IS NULL THEN
        RAISE EXCEPTION 'missing table: oidc_refresh_tokens';
    END IF;
    IF to_regclass('public.oidc_access_tokens') IS NULL THEN
        RAISE EXCEPTION 'missing table: oidc_access_tokens';
    END IF;
    IF to_regclass('public.saml_service_providers') IS NULL THEN
        RAISE EXCEPTION 'missing table: saml_service_providers';
    END IF;
    IF to_regclass('public.saml_login_sessions') IS NULL THEN
        RAISE EXCEPTION 'missing table: saml_login_sessions';
    END IF;
    IF to_regclass('public.cas_tickets') IS NULL THEN
        RAISE EXCEPTION 'missing table: cas_tickets';
    END IF;
END $$;

DO $$
DECLARE
    tenant_one UUID;
    tenant_two UUID;
    user_one UUID;
    session_one UUID;
    group_one UUID;
    role_one UUID;
    permission_one UUID;
    oidc_client_one UUID;
    saml_app_one UUID;
    saml_login_session_one UUID;
    cas_tgt_one UUID;
BEGIN
    INSERT INTO tenants (name, slug, status)
    VALUES ('Tenant One', 'tenant-one', 'active')
    RETURNING id INTO tenant_one;

    INSERT INTO tenants (name, slug, status)
    VALUES ('Tenant Two', 'tenant-two', 'active')
    RETURNING id INTO tenant_two;

    INSERT INTO users (
        tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source
    ) VALUES (
        tenant_one, 'alice', 'alice@tenant-one.test', '+10000000001', 'Alice One', 'hashed-password', 'argon2id', 'active', 'local'
    ) RETURNING id INTO user_one;

    INSERT INTO users (
        tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source
    ) VALUES (
        tenant_two, 'alice', 'alice@tenant-one.test', '+10000000002', 'Alice Two', 'hashed-password', 'argon2id', 'active', 'local'
    );

    INSERT INTO auth_sessions (
        tenant_id, user_id, sid, login_method, mfa_verified, ip, user_agent, status, expires_at, last_seen_at
    ) VALUES (
        tenant_one, user_one, repeat('a', 64), 'username', FALSE, '127.0.0.1', 'verify-script', 'active', NOW() + INTERVAL '1 day', NOW()
    ) RETURNING id INTO session_one;

    BEGIN
        INSERT INTO auth_sessions (
            tenant_id, user_id, sid, login_method, mfa_verified, ip, user_agent, status, expires_at, last_seen_at
        ) VALUES (
            tenant_one, user_one, repeat('a', 64), 'username', FALSE, '127.0.0.2', 'verify-script', 'active', NOW() + INTERVAL '1 day', NOW()
        );
        RAISE EXCEPTION 'expected unique violation on auth_sessions.sid';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO users (
            tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source
        ) VALUES (
            tenant_one, 'alice', 'other@tenant-one.test', '+10000000003', 'Dup Username', 'hashed-password', 'argon2id', 'active', 'local'
        );
        RAISE EXCEPTION 'expected unique violation on users (tenant_id, username)';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO users (
            tenant_id, username, email, phone, display_name, password_hash, password_algo, status, source
        ) VALUES (
            tenant_one, 'alice-two', 'alice@tenant-one.test', '+10000000004', 'Dup Email', 'hashed-password', 'argon2id', 'active', 'local'
        );
        RAISE EXCEPTION 'expected unique violation on users (tenant_id, email)';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    INSERT INTO user_profiles (user_id, avatar_url, title, department, locale, timezone)
    VALUES (user_one, 'https://example.test/avatar.png', 'Engineer', 'Platform', 'en-US', 'UTC');

    INSERT INTO groups (tenant_id, name, code, description)
    VALUES (tenant_one, 'Platform', 'platform', 'Platform group')
    RETURNING id INTO group_one;

    BEGIN
        INSERT INTO groups (tenant_id, name, code, description)
        VALUES (tenant_one, 'Platform Duplicate', 'platform', 'Duplicate code');
        RAISE EXCEPTION 'expected unique violation on groups (tenant_id, code)';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    INSERT INTO user_groups (user_id, group_id) VALUES (user_one, group_one);

    BEGIN
        INSERT INTO user_groups (user_id, group_id) VALUES (user_one, group_one);
        RAISE EXCEPTION 'expected duplicate protection on user_groups';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    INSERT INTO roles (tenant_id, name, code, description)
    VALUES (tenant_one, 'Tenant Admin', 'tenant_admin', 'Tenant admin role')
    RETURNING id INTO role_one;

    BEGIN
        INSERT INTO roles (tenant_id, name, code, description)
        VALUES (tenant_one, 'Tenant Admin Duplicate', 'tenant_admin', 'Duplicate role code');
        RAISE EXCEPTION 'expected unique violation on roles (tenant_id, code)';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    INSERT INTO permissions (tenant_id, resource, action, effect, description)
    VALUES (tenant_one, 'users', 'read', 'allow', 'Read users')
    RETURNING id INTO permission_one;

    INSERT INTO role_permissions (role_id, permission_id) VALUES (role_one, permission_one);
    INSERT INTO user_roles (user_id, role_id) VALUES (user_one, role_one);

    INSERT INTO applications (
        tenant_id, name, code, type, status, homepage_url, icon_url, description
    ) VALUES (
        tenant_one, 'Admin Console', 'admin-console', 'oidc-client', 'active',
        'https://admin.example.test', 'https://admin.example.test/icon.png', 'Admin frontend'
    );

    INSERT INTO oidc_clients (
        tenant_id, app_id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
        grant_types, response_types, scopes, token_endpoint_auth_method, require_pkce,
        access_token_ttl, refresh_token_ttl, id_token_signed_response_alg
    )
    SELECT
        tenant_one,
        id,
        'verify-public-client',
        NULL,
        ARRAY['https://client.example.test/callback'],
        ARRAY['https://client.example.test/logout-callback'],
        ARRAY['authorization_code', 'refresh_token'],
        ARRAY['code'],
        ARRAY['openid', 'profile', 'email'],
        'none',
        TRUE,
        600,
        3600,
        'RS256'
    FROM applications
    WHERE tenant_id = tenant_one AND code = 'admin-console'
    RETURNING id INTO oidc_client_one;

    BEGIN
        INSERT INTO oidc_clients (
            tenant_id, app_id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, response_types, scopes, token_endpoint_auth_method, require_pkce,
            access_token_ttl, refresh_token_ttl, id_token_signed_response_alg
        )
        SELECT
            tenant_one,
            id,
            'verify-public-client',
            NULL,
            ARRAY['https://client2.example.test/callback'],
            ARRAY[]::TEXT[],
            ARRAY['authorization_code'],
            ARRAY['code'],
            ARRAY['openid'],
            'none',
            TRUE,
            600,
            3600,
            'RS256'
        FROM applications
        WHERE tenant_id = tenant_one AND code = 'admin-console';
        RAISE EXCEPTION 'expected unique violation on oidc_clients.client_id';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    INSERT INTO oidc_authorization_codes (
        oidc_client_id, tenant_id, user_id, session_id, code_hash, redirect_uri, scopes,
        nonce, code_challenge, code_challenge_method, expires_at
    ) VALUES (
        oidc_client_one, tenant_one, user_one, session_one, repeat('b', 64),
        'https://client.example.test/callback', ARRAY['openid', 'profile'],
        'nonce-verify', 'challenge-verify', 'S256', NOW() + INTERVAL '5 minutes'
    );

    INSERT INTO oidc_refresh_tokens (
        oidc_client_id, client_id, tenant_id, user_id, session_id, token_hash, scopes, expires_at
    ) VALUES (
        oidc_client_one, 'verify-public-client', tenant_one, user_one, session_one, repeat('c', 64),
        ARRAY['openid', 'profile'], NOW() + INTERVAL '1 day'
    );

    INSERT INTO oidc_access_tokens (
        oidc_client_id, client_id, tenant_id, user_id, session_id, token_hash, scopes, expires_at
    ) VALUES (
        oidc_client_one, 'verify-public-client', tenant_one, user_one, session_one, repeat('d', 64),
        ARRAY['openid', 'profile'], NOW() + INTERVAL '10 minutes'
    );

    INSERT INTO applications (
        tenant_id, name, code, type, status, homepage_url, icon_url, description
    ) VALUES (
        tenant_one, 'SAML Demo', 'saml-demo', 'saml-sp', 'active',
        'https://saml.example.test', '', 'SAML demo app'
    ) RETURNING id INTO saml_app_one;

    INSERT INTO saml_service_providers (
        app_id, entity_id, acs_url, slo_url, nameid_format, want_assertions_signed, want_response_signed,
        sign_authn_request, encrypt_assertion, sp_metadata_xml, sp_x509_cert, attribute_mapping_jsonb
    ) VALUES (
        saml_app_one,
        'https://sp.example.test/metadata',
        'https://sp.example.test/saml/acs',
        'https://sp.example.test/saml/slo',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        TRUE,
        FALSE,
        FALSE,
        FALSE,
        '<EntityDescriptor/>',
        'MIICVERIFYCERT',
        '{"email":"email"}'::jsonb
    );

    INSERT INTO saml_login_sessions (
        app_id, user_id, session_id, name_id, session_index, status, issued_at, expires_at
    ) VALUES (
        saml_app_one,
        user_one,
        session_one,
        'alice@tenant-one.test',
        session_one::text,
        'active',
        NOW(),
        NOW() + INTERVAL '1 day'
    ) RETURNING id INTO saml_login_session_one;

    BEGIN
        INSERT INTO saml_login_sessions (
            app_id, user_id, session_id, name_id, session_index, status, issued_at, expires_at
        ) VALUES (
            saml_app_one,
            user_one,
            session_one,
            'alice@tenant-one.test',
            session_one::text,
            'active',
            NOW(),
            NOW() + INTERVAL '1 day'
        );
        RAISE EXCEPTION 'expected unique violation on saml_login_sessions (app_id, session_id)';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    INSERT INTO cas_tickets (
        ticket, type, service, user_id, session_id, parent_ticket_id, expires_at
    ) VALUES (
        repeat('e', 64),
        'TGT',
        NULL,
        user_one,
        session_one,
        NULL,
        NOW() + INTERVAL '1 day'
    ) RETURNING id INTO cas_tgt_one;

    INSERT INTO cas_tickets (
        ticket, type, service, user_id, session_id, parent_ticket_id, expires_at
    ) VALUES (
        repeat('f', 64),
        'ST',
        'https://service.example.test/cas',
        user_one,
        session_one,
        cas_tgt_one,
        NOW() + INTERVAL '5 minutes'
    );

    BEGIN
        INSERT INTO cas_tickets (
            ticket, type, service, user_id, session_id, parent_ticket_id, expires_at
        ) VALUES (
            repeat('f', 64),
            'ST',
            'https://service.example.test/cas',
            user_one,
            session_one,
            cas_tgt_one,
            NOW() + INTERVAL '5 minutes'
        );
        RAISE EXCEPTION 'expected unique violation on cas_tickets.ticket';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO applications (
            tenant_id, name, code, type, status, homepage_url, icon_url, description
        ) VALUES (
            tenant_one, 'SAML Demo Two', 'saml-demo-two', 'saml-sp', 'active',
            'https://saml2.example.test', '', 'SAML demo app two'
        ) RETURNING id INTO saml_app_one;

        INSERT INTO saml_service_providers (
            app_id, entity_id, acs_url, slo_url, nameid_format
        ) VALUES (
            saml_app_one,
            'https://sp.example.test/metadata',
            'https://sp2.example.test/saml/acs',
            '',
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        );
        RAISE EXCEPTION 'expected unique violation on saml_service_providers.entity_id';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;

    BEGIN
        INSERT INTO applications (
            tenant_id, name, code, type, status, homepage_url, icon_url, description
        ) VALUES (
            tenant_one, 'Admin Console Duplicate', 'admin-console', 'oidc-client', 'active',
            'https://admin2.example.test', 'https://admin2.example.test/icon.png', 'Duplicate app code'
        );
        RAISE EXCEPTION 'expected unique violation on applications (tenant_id, code)';
    EXCEPTION
        WHEN unique_violation THEN NULL;
    END;
END $$;
'@

Invoke-Psql -Database $VerifyDatabase -Sql $verifyUp

$applyDown = "ls /migrations/*.down.sql | sort -r | while read file; do psql -v ON_ERROR_STOP=1 -U $PostgresUser -d $VerifyDatabase -f `$file; done"
Invoke-Compose -Args @("exec", "-T", $PostgresService, "sh", "-lc", $applyDown)

$verifyDown = @'
DO $$
BEGIN
    IF to_regclass('public.auth_sessions') IS NOT NULL THEN
        RAISE EXCEPTION 'auth_sessions table should have been dropped';
    END IF;
    IF to_regclass('public.oidc_refresh_tokens') IS NOT NULL THEN
        RAISE EXCEPTION 'oidc_refresh_tokens table should have been dropped';
    END IF;
    IF to_regclass('public.oidc_access_tokens') IS NOT NULL THEN
        RAISE EXCEPTION 'oidc_access_tokens table should have been dropped';
    END IF;
    IF to_regclass('public.oidc_authorization_codes') IS NOT NULL THEN
        RAISE EXCEPTION 'oidc_authorization_codes table should have been dropped';
    END IF;
    IF to_regclass('public.saml_service_providers') IS NOT NULL THEN
        RAISE EXCEPTION 'saml_service_providers table should have been dropped';
    END IF;
    IF to_regclass('public.saml_login_sessions') IS NOT NULL THEN
        RAISE EXCEPTION 'saml_login_sessions table should have been dropped';
    END IF;
    IF to_regclass('public.cas_tickets') IS NOT NULL THEN
        RAISE EXCEPTION 'cas_tickets table should have been dropped';
    END IF;
    IF to_regclass('public.oidc_clients') IS NOT NULL THEN
        RAISE EXCEPTION 'oidc_clients table should have been dropped';
    END IF;
    IF to_regclass('public.applications') IS NOT NULL THEN
        RAISE EXCEPTION 'applications table should have been dropped';
    END IF;
    IF to_regclass('public.user_roles') IS NOT NULL THEN
        RAISE EXCEPTION 'user_roles table should have been dropped';
    END IF;
    IF to_regclass('public.role_permissions') IS NOT NULL THEN
        RAISE EXCEPTION 'role_permissions table should have been dropped';
    END IF;
    IF to_regclass('public.permissions') IS NOT NULL THEN
        RAISE EXCEPTION 'permissions table should have been dropped';
    END IF;
    IF to_regclass('public.roles') IS NOT NULL THEN
        RAISE EXCEPTION 'roles table should have been dropped';
    END IF;
    IF to_regclass('public.user_groups') IS NOT NULL THEN
        RAISE EXCEPTION 'user_groups table should have been dropped';
    END IF;
    IF to_regclass('public.groups') IS NOT NULL THEN
        RAISE EXCEPTION 'groups table should have been dropped';
    END IF;
    IF to_regclass('public.user_profiles') IS NOT NULL THEN
        RAISE EXCEPTION 'user_profiles table should have been dropped';
    END IF;
    IF to_regclass('public.users') IS NOT NULL THEN
        RAISE EXCEPTION 'users table should have been dropped';
    END IF;
    IF to_regclass('public.tenants') IS NOT NULL THEN
        RAISE EXCEPTION 'tenants table should have been dropped';
    END IF;
END $$;
'@

Invoke-Psql -Database $VerifyDatabase -Sql $verifyDown
Invoke-Compose -Args @("exec", "-T", $PostgresService, "psql", "-v", "ON_ERROR_STOP=1", "-U", $PostgresUser, "-d", "postgres", "-c", "DROP DATABASE IF EXISTS $VerifyDatabase WITH (FORCE);")

Write-Host "Migration verification completed successfully."
