package service

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	appsdomain "github.com/miloyuans/openauthing/internal/apps/domain"
	"github.com/miloyuans/openauthing/internal/config"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
	"github.com/miloyuans/openauthing/internal/store"
)

func TestIDPMetadataIncludesRequiredElements(t *testing.T) {
	svc := NewService(
		config.SAMLConfig{IDPEntityID: "https://iam.example.test/saml/idp/metadata"},
		"https://iam.example.test",
		nil,
		nil,
		stubCertificateManager{certificate: "BASE64CERT"},
	)

	raw, err := svc.IDPMetadata()
	if err != nil {
		t.Fatalf("generate metadata: %v", err)
	}

	body := string(raw)
	for _, expected := range []string{
		`entityID="https://iam.example.test/saml/idp/metadata"`,
		"SingleSignOnService",
		"SingleLogoutService",
		"BASE64CERT",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q in metadata xml: %s", expected, body)
		}
	}
}

func TestImportMetadataParsesAndStoresServiceProvider(t *testing.T) {
	appID := uuid.New()
	appRepo := stubApplicationRepository{
		app: appsdomain.Application{
			ID:   appID,
			Type: appsdomain.TypeSAMLSP,
		},
	}
	repo := newStubServiceProviderRepository()
	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, repo, stubCertificateManager{certificate: "BASE64CERT"})

	result, err := svc.ImportMetadata(context.Background(), appID.String(), sampleSPMetadataXML)
	if err != nil {
		t.Fatalf("import metadata: %v", err)
	}

	if result.EntityID != "https://sp.example.test/metadata" {
		t.Fatalf("unexpected entity id: %#v", result)
	}

	if result.ACSURL != "https://sp.example.test/saml/acs" {
		t.Fatalf("unexpected acs_url: %#v", result)
	}

	if result.SLOURL != "https://sp.example.test/saml/slo" {
		t.Fatalf("unexpected slo_url: %#v", result)
	}

	if !result.WantAssertionsSigned || !result.SignAuthnRequest || !result.EncryptAssertion {
		t.Fatalf("unexpected signing/encryption flags: %#v", result)
	}

	if result.SPX509Cert != "MIICSPCERTDATA" {
		t.Fatalf("unexpected certificate content: %q", result.SPX509Cert)
	}
}

func TestGetByAppIDReturnsStoredConfiguration(t *testing.T) {
	appID := uuid.New()
	appRepo := stubApplicationRepository{
		app: appsdomain.Application{
			ID:   appID,
			Type: appsdomain.TypeSAMLSP,
		},
	}
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:     appID,
		EntityID:  "https://sp.example.test/metadata",
		ACSURL:    "https://sp.example.test/saml/acs",
		SLOURL:    "https://sp.example.test/saml/slo",
		NameIDFormat: samldomain.DefaultNameIDFormat,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, repo, stubCertificateManager{certificate: "BASE64CERT"})
	result, err := svc.GetByAppID(context.Background(), appID.String())
	if err != nil {
		t.Fatalf("get service provider: %v", err)
	}

	if result.EntityID != "https://sp.example.test/metadata" {
		t.Fatalf("unexpected entity id: %#v", result)
	}
}

type stubApplicationRepository struct {
	app appsdomain.Application
	err error
}

func (s stubApplicationRepository) GetByID(ctx context.Context, id uuid.UUID) (appsdomain.Application, error) {
	if s.err != nil {
		return appsdomain.Application{}, s.err
	}
	if s.app.ID != id {
		return appsdomain.Application{}, store.ErrNotFound
	}
	return s.app, nil
}

type stubServiceProviderRepository struct {
	items map[uuid.UUID]samldomain.ServiceProvider
}

func newStubServiceProviderRepository() *stubServiceProviderRepository {
	return &stubServiceProviderRepository{items: map[uuid.UUID]samldomain.ServiceProvider{}}
}

func (s *stubServiceProviderRepository) GetByAppID(ctx context.Context, appID uuid.UUID) (samldomain.ServiceProvider, error) {
	item, ok := s.items[appID]
	if !ok {
		return samldomain.ServiceProvider{}, store.ErrNotFound
	}
	return item, nil
}

func (s *stubServiceProviderRepository) Upsert(ctx context.Context, sp samldomain.ServiceProvider) (samldomain.ServiceProvider, error) {
	s.items[sp.AppID] = sp
	return sp, nil
}

type stubCertificateManager struct {
	certificate string
}

func (s stubCertificateManager) MetadataCertificate() string {
	return s.certificate
}

const sampleSPMetadataXML = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true" AuthnRequestsSigned="true">
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>
            MIICSPCERTDATA
          </X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.test/saml/acs" index="0"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.test/saml/slo"/>
  </SPSSODescriptor>
</EntityDescriptor>`
