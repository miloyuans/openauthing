\set ON_ERROR_STOP on

INSERT INTO groups (
    id, tenant_id, name, code, description
) VALUES (
    :'group_id'::uuid,
    :'tenant_id'::uuid,
    'Jump Operators',
    'jump_ops',
    'JumpServer demo operators group'
)
ON CONFLICT (tenant_id, code) DO UPDATE
SET name = EXCLUDED.name,
    description = EXCLUDED.description,
    updated_at = NOW();

INSERT INTO roles (
    id, tenant_id, name, code, description
) VALUES (
    :'role_id'::uuid,
    :'tenant_id'::uuid,
    'Jump User',
    'jump_user',
    'JumpServer demo role'
)
ON CONFLICT (tenant_id, code) DO UPDATE
SET name = EXCLUDED.name,
    description = EXCLUDED.description,
    updated_at = NOW();

INSERT INTO user_groups (user_id, group_id)
VALUES (
    :'user_id'::uuid,
    :'group_id'::uuid
)
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
VALUES (
    :'user_id'::uuid,
    :'role_id'::uuid
)
ON CONFLICT DO NOTHING;
