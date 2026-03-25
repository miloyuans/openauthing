package repo

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/saml/domain"
	"github.com/miloyuans/openauthing/internal/store"
	postgresstore "github.com/miloyuans/openauthing/internal/store/postgres"
)

type PostgresServiceProviderRepository struct {
	store *postgresstore.Store
}

func NewPostgresServiceProviderRepository(store *postgresstore.Store) *PostgresServiceProviderRepository {
	return &PostgresServiceProviderRepository{store: store}
}

func (r *PostgresServiceProviderRepository) GetByAppID(ctx context.Context, appID uuid.UUID) (domain.ServiceProvider, error) {
	row := r.store.Executor(ctx).QueryRowContext(ctx, `
SELECT app_id, entity_id, acs_url, slo_url, nameid_format, want_assertions_signed, want_response_signed,
       sign_authn_request, encrypt_assertion, sp_metadata_xml, sp_x509_cert, attribute_mapping_jsonb,
       created_at, updated_at
FROM saml_service_providers
WHERE app_id = $1`, appID)

	return scanServiceProvider(row)
}

func (r *PostgresServiceProviderRepository) GetByEntityID(ctx context.Context, entityID string) (domain.ServiceProvider, error) {
	row := r.store.Executor(ctx).QueryRowContext(ctx, `
SELECT app_id, entity_id, acs_url, slo_url, nameid_format, want_assertions_signed, want_response_signed,
       sign_authn_request, encrypt_assertion, sp_metadata_xml, sp_x509_cert, attribute_mapping_jsonb,
       created_at, updated_at
FROM saml_service_providers
WHERE entity_id = $1`, entityID)

	return scanServiceProvider(row)
}

func (r *PostgresServiceProviderRepository) Upsert(ctx context.Context, sp domain.ServiceProvider) (domain.ServiceProvider, error) {
	attributeMapping, err := marshalAttributeMapping(sp.AttributeMapping)
	if err != nil {
		return domain.ServiceProvider{}, err
	}

	row := r.store.Executor(ctx).QueryRowContext(ctx, `
INSERT INTO saml_service_providers (
    app_id, entity_id, acs_url, slo_url, nameid_format, want_assertions_signed, want_response_signed,
    sign_authn_request, encrypt_assertion, sp_metadata_xml, sp_x509_cert, attribute_mapping_jsonb
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
    updated_at = NOW()
RETURNING app_id, entity_id, acs_url, slo_url, nameid_format, want_assertions_signed, want_response_signed,
          sign_authn_request, encrypt_assertion, sp_metadata_xml, sp_x509_cert, attribute_mapping_jsonb,
          created_at, updated_at`,
		sp.AppID,
		sp.EntityID,
		sp.ACSURL,
		sp.SLOURL,
		sp.NameIDFormat,
		sp.WantAssertionsSigned,
		sp.WantResponseSigned,
		sp.SignAuthnRequest,
		sp.EncryptAssertion,
		sp.SPMetadataXML,
		sp.SPX509Cert,
		attributeMapping,
	)

	return scanServiceProvider(row)
}

type scannable interface {
	Scan(dest ...any) error
}

func scanServiceProvider(row scannable) (domain.ServiceProvider, error) {
	var (
		sp                  domain.ServiceProvider
		attributeMappingRaw []byte
	)

	if err := row.Scan(
		&sp.AppID,
		&sp.EntityID,
		&sp.ACSURL,
		&sp.SLOURL,
		&sp.NameIDFormat,
		&sp.WantAssertionsSigned,
		&sp.WantResponseSigned,
		&sp.SignAuthnRequest,
		&sp.EncryptAssertion,
		&sp.SPMetadataXML,
		&sp.SPX509Cert,
		&attributeMappingRaw,
		&sp.CreatedAt,
		&sp.UpdatedAt,
	); err != nil {
		return domain.ServiceProvider{}, store.NormalizeError(err)
	}

	sp.AttributeMapping = map[string]string{}
	if len(attributeMappingRaw) > 0 {
		if err := json.Unmarshal(attributeMappingRaw, &sp.AttributeMapping); err != nil {
			return domain.ServiceProvider{}, err
		}
	}

	return sp, nil
}

func marshalAttributeMapping(value map[string]string) ([]byte, error) {
	if len(value) == 0 {
		return []byte("{}"), nil
	}

	return json.Marshal(value)
}
