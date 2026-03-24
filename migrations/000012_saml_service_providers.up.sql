CREATE TABLE saml_service_providers (
    app_id UUID PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    entity_id VARCHAR(2048) NOT NULL,
    acs_url VARCHAR(2048) NOT NULL,
    slo_url VARCHAR(2048) NOT NULL DEFAULT '',
    nameid_format VARCHAR(255) NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    want_assertions_signed BOOLEAN NOT NULL DEFAULT TRUE,
    want_response_signed BOOLEAN NOT NULL DEFAULT FALSE,
    sign_authn_request BOOLEAN NOT NULL DEFAULT FALSE,
    encrypt_assertion BOOLEAN NOT NULL DEFAULT FALSE,
    sp_metadata_xml TEXT NOT NULL DEFAULT '',
    sp_x509_cert TEXT NOT NULL DEFAULT '',
    attribute_mapping_jsonb JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX saml_service_providers_entity_id_uidx ON saml_service_providers (entity_id);
