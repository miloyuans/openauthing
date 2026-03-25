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
    :'saml_app_id'::uuid,
    :'tenant_id'::uuid,
    :'saml_app_name',
    :'saml_app_code',
    'saml-sp',
    'active',
    :'aws_iic_access_portal_url',
    '',
    'AWS IAM Identity Center SAML demo service provider'
)
ON CONFLICT (tenant_id, code) DO UPDATE
SET name = EXCLUDED.name,
    type = EXCLUDED.type,
    status = EXCLUDED.status,
    homepage_url = EXCLUDED.homepage_url,
    description = EXCLUDED.description,
    updated_at = NOW();

INSERT INTO saml_service_providers (
    app_id,
    entity_id,
    acs_url,
    slo_url,
    nameid_format,
    want_assertions_signed,
    want_response_signed,
    sign_authn_request,
    encrypt_assertion,
    sp_metadata_xml,
    sp_x509_cert,
    attribute_mapping_jsonb
) VALUES (
    :'saml_app_id'::uuid,
    :'aws_iic_saml_entity_id',
    :'aws_iic_saml_acs_url',
    :'aws_iic_saml_slo_url',
    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    :'aws_iic_sp_metadata_xml',
    '',
    '{"username":"username","email":"email","name":"displayName","groups":"groups"}'::jsonb
)
ON CONFLICT (app_id) DO UPDATE
SET entity_id = EXCLUDED.entity_id,
    acs_url = EXCLUDED.acs_url,
    slo_url = EXCLUDED.slo_url,
    nameid_format = EXCLUDED.nameid_format,
    want_assertions_signed = EXCLUDED.want_assertions_signed,
    want_response_signed = EXCLUDED.want_response_signed,
    sign_authn_request = EXCLUDED.sign_authn_request,
    encrypt_assertion = EXCLUDED.encrypt_assertion,
    sp_metadata_xml = EXCLUDED.sp_metadata_xml,
    sp_x509_cert = EXCLUDED.sp_x509_cert,
    attribute_mapping_jsonb = EXCLUDED.attribute_mapping_jsonb,
    updated_at = NOW();

INSERT INTO applications (
    id, tenant_id, name, code, type, status, homepage_url, icon_url, description
) VALUES (
    :'scim_app_id'::uuid,
    :'tenant_id'::uuid,
    :'scim_app_name',
    :'scim_app_code',
    'scim-target',
    'active',
    :'aws_iic_scim_endpoint',
    '',
    'AWS IAM Identity Center SCIM target placeholder; keep the SCIM bearer token outside the database'
)
ON CONFLICT (tenant_id, code) DO UPDATE
SET name = EXCLUDED.name,
    type = EXCLUDED.type,
    status = EXCLUDED.status,
    homepage_url = EXCLUDED.homepage_url,
    description = EXCLUDED.description,
    updated_at = NOW();

INSERT INTO groups (
    id, tenant_id, name, code, description
) VALUES (
    :'group_id'::uuid,
    :'tenant_id'::uuid,
    :'group_name',
    :'group_code',
    'AWS IAM Identity Center demo group for SCIM sync'
)
ON CONFLICT (tenant_id, code) DO UPDATE
SET name = EXCLUDED.name,
    description = EXCLUDED.description,
    updated_at = NOW();

INSERT INTO users (
    id,
    tenant_id,
    username,
    email,
    phone,
    display_name,
    password_hash,
    password_algo,
    status,
    source
) VALUES (
    :'demo_user_id'::uuid,
    :'tenant_id'::uuid,
    :'demo_username',
    :'demo_email',
    '',
    :'demo_display_name',
    :'demo_password_hash',
    'argon2id',
    'active',
    'local'
)
ON CONFLICT (tenant_id, username) DO UPDATE
SET email = EXCLUDED.email,
    display_name = EXCLUDED.display_name,
    password_hash = EXCLUDED.password_hash,
    password_algo = EXCLUDED.password_algo,
    status = EXCLUDED.status,
    source = EXCLUDED.source,
    updated_at = NOW();

INSERT INTO user_groups (user_id, group_id)
VALUES (
    :'demo_user_id'::uuid,
    :'group_id'::uuid
)
ON CONFLICT DO NOTHING;
