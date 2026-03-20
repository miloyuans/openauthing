CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(120) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT tenants_status_check CHECK (status IN ('active', 'disabled'))
);

CREATE UNIQUE INDEX tenants_slug_uidx ON tenants (slug);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(64) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(32),
    display_name VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    password_algo VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    source VARCHAR(32) NOT NULL DEFAULT 'local',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'locked')),
    CONSTRAINT users_source_check CHECK (source IN ('local', 'scim', 'ldap-import'))
);

CREATE INDEX users_tenant_id_idx ON users (tenant_id);
CREATE UNIQUE INDEX users_tenant_username_uidx ON users (tenant_id, username);
CREATE UNIQUE INDEX users_tenant_email_uidx ON users (tenant_id, email) WHERE email IS NOT NULL;

CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    avatar_url VARCHAR(2048),
    title VARCHAR(120),
    department VARCHAR(120),
    locale VARCHAR(32),
    timezone VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    code VARCHAR(64) NOT NULL,
    description VARCHAR(500) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX groups_tenant_id_idx ON groups (tenant_id);
CREATE UNIQUE INDEX groups_tenant_code_uidx ON groups (tenant_id, code);

CREATE TABLE user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX user_groups_group_id_user_id_idx ON user_groups (group_id, user_id);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    code VARCHAR(64) NOT NULL,
    description VARCHAR(500) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX roles_tenant_id_idx ON roles (tenant_id);
CREATE UNIQUE INDEX roles_tenant_code_uidx ON roles (tenant_id, code);

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    resource VARCHAR(128) NOT NULL,
    action VARCHAR(64) NOT NULL,
    effect VARCHAR(16) NOT NULL DEFAULT 'allow',
    description VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT permissions_effect_check CHECK (effect IN ('allow', 'deny'))
);

CREATE INDEX permissions_tenant_id_idx ON permissions (tenant_id);
CREATE UNIQUE INDEX permissions_tenant_resource_action_effect_uidx
    ON permissions (tenant_id, resource, action, effect);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX role_permissions_permission_id_role_id_idx ON role_permissions (permission_id, role_id);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_id_user_id_idx ON user_roles (role_id, user_id);

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    code VARCHAR(64) NOT NULL,
    type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    homepage_url VARCHAR(2048) NOT NULL DEFAULT '',
    icon_url VARCHAR(2048) NOT NULL DEFAULT '',
    description VARCHAR(1000) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT applications_type_check CHECK (
        type IN ('oidc-client', 'saml-sp', 'cas-service', 'ldap-client', 'scim-target')
    ),
    CONSTRAINT applications_status_check CHECK (status IN ('active', 'disabled', 'draft'))
);

CREATE INDEX applications_tenant_id_idx ON applications (tenant_id);
CREATE UNIQUE INDEX applications_tenant_code_uidx ON applications (tenant_id, code);
