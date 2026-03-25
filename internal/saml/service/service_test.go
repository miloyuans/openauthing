package service

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/russellhaering/goxmldsig"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	appsdomain "github.com/miloyuans/openauthing/internal/apps/domain"
	"github.com/miloyuans/openauthing/internal/config"
	samlkeys "github.com/miloyuans/openauthing/internal/saml/keys"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
	"github.com/miloyuans/openauthing/internal/store"
	userdomain "github.com/miloyuans/openauthing/internal/usercenter/domain"
)

func TestIDPMetadataIncludesRequiredElements(t *testing.T) {
	svc := NewService(
		config.SAMLConfig{IDPEntityID: "https://iam.example.test/saml/idp/metadata"},
		"https://iam.example.test",
		nil,
		nil,
		nil,
		stubCertificateManager{metadataCertificate: "BASE64CERT"},
		"test-secret",
		nil,
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
			ID:     appID,
			Type:   appsdomain.TypeSAMLSP,
			Status: appsdomain.StatusActive,
		},
	}
	repo := newStubServiceProviderRepository()
	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, nil, repo, stubCertificateManager{metadataCertificate: "BASE64CERT"}, "test-secret", nil)

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
			ID:     appID,
			Type:   appsdomain.TypeSAMLSP,
			Status: appsdomain.StatusActive,
		},
	}
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:        appID,
		EntityID:     "https://sp.example.test/metadata",
		ACSURL:       "https://sp.example.test/saml/acs",
		SLOURL:       "https://sp.example.test/saml/slo",
		NameIDFormat: samldomain.DefaultNameIDFormat,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, nil, repo, stubCertificateManager{metadataCertificate: "BASE64CERT"}, "test-secret", nil)
	result, err := svc.GetByAppID(context.Background(), appID.String())
	if err != nil {
		t.Fatalf("get service provider: %v", err)
	}

	if result.EntityID != "https://sp.example.test/metadata" {
		t.Fatalf("unexpected entity id: %#v", result)
	}
}

func TestCompleteSPInitiatedReturnsSignedAssertion(t *testing.T) {
	appID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	appRepo := stubApplicationRepository{
		app: appsdomain.Application{
			ID:       appID,
			TenantID: tenantID,
			Type:     appsdomain.TypeSAMLSP,
			Status:   appsdomain.StatusActive,
		},
	}
	userRepo := stubUserRepository{
		user: authTestUser(userID, tenantID),
		groups: []string{
			"platform",
			"sre",
		},
	}
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:                appID,
		EntityID:             "https://sp.example.test/metadata",
		ACSURL:               "https://sp.example.test/saml/acs",
		NameIDFormat:         samldomain.NameIDFormatPersistent,
		WantAssertionsSigned: true,
		AttributeMapping: map[string]string{
			"username": "preferred_username",
			"email":    "email",
			"name":     "name",
			"groups":   "groups",
		},
	}

	keyManager := newTestKeyManager(t)
	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, userRepo, repo, keyManager, "test-session-secret", nil)
	svc.now = func() time.Time { return time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC) }

	result, err := svc.CompleteSPInitiated(context.Background(), authdomain.Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		ExpiresAt: svc.now().Add(24 * time.Hour),
	}, samldomain.SPInitiatedRequest{
		Binding:     samldomain.BindingHTTPRedirect,
		SAMLRequest: mustDeflatedAuthnRequest(t, sampleAuthnRequestXML("https://iam.example.test/saml/idp/sso")),
		RelayState:  "relay-123",
	})
	if err != nil {
		t.Fatalf("complete sp initiated sso: %v", err)
	}

	if result.ACSURL != "https://sp.example.test/saml/acs" {
		t.Fatalf("unexpected acs url: %#v", result)
	}
	if result.RelayState != "relay-123" {
		t.Fatalf("unexpected relay state: %q", result.RelayState)
	}

	responseXML := mustDecodeSAMLResponse(t, result.SAMLResponse)
	if !strings.Contains(responseXML, "samlp:Response") || !strings.Contains(responseXML, "saml:Assertion") {
		t.Fatalf("expected SAML response xml, got %s", responseXML)
	}
	if !strings.Contains(responseXML, "preferred_username") || !strings.Contains(responseXML, "alice") {
		t.Fatalf("expected mapped username attribute in response: %s", responseXML)
	}
	if !strings.Contains(responseXML, "groups") || !strings.Contains(responseXML, "platform") {
		t.Fatalf("expected groups attribute in response: %s", responseXML)
	}

	assertion := mustFindElement(t, responseXML, "saml:Assertion")
	validateSignature(t, assertion, keyManager.Certificate())
}

func TestCompleteIDPInitiatedReturnsTargetACS(t *testing.T) {
	appID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	appRepo := stubApplicationRepository{
		app: appsdomain.Application{
			ID:       appID,
			TenantID: tenantID,
			Type:     appsdomain.TypeSAMLSP,
			Status:   appsdomain.StatusActive,
		},
	}
	userRepo := stubUserRepository{user: authTestUser(userID, tenantID)}
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:                appID,
		EntityID:             "https://sp.example.test/metadata",
		ACSURL:               "https://sp.example.test/saml/acs",
		NameIDFormat:         samldomain.DefaultNameIDFormat,
		WantAssertionsSigned: true,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, userRepo, repo, newTestKeyManager(t), "test-session-secret", nil)
	result, err := svc.CompleteIDPInitiated(context.Background(), authdomain.Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, appID.String(), "")
	if err != nil {
		t.Fatalf("complete idp initiated sso: %v", err)
	}

	if result.ACSURL != "https://sp.example.test/saml/acs" {
		t.Fatalf("unexpected acs url: %#v", result)
	}

	responseXML := mustDecodeSAMLResponse(t, result.SAMLResponse)
	if strings.Contains(responseXML, `InResponseTo="`) {
		t.Fatalf("idp-initiated response should not set InResponseTo: %s", responseXML)
	}
}

func TestCompleteSPInitiatedCanSignResponse(t *testing.T) {
	appID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	appRepo := stubApplicationRepository{
		app: appsdomain.Application{
			ID:       appID,
			TenantID: tenantID,
			Type:     appsdomain.TypeSAMLSP,
			Status:   appsdomain.StatusActive,
		},
	}
	userRepo := stubUserRepository{user: authTestUser(userID, tenantID)}
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:                appID,
		EntityID:             "https://sp.example.test/metadata",
		ACSURL:               "https://sp.example.test/saml/acs",
		NameIDFormat:         samldomain.DefaultNameIDFormat,
		WantAssertionsSigned: true,
		WantResponseSigned:   true,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, userRepo, repo, newTestKeyManager(t), "test-session-secret", nil)
	result, err := svc.CompleteSPInitiated(context.Background(), authdomain.Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, samldomain.SPInitiatedRequest{
		Binding:     samldomain.BindingHTTPRedirect,
		SAMLRequest: mustDeflatedAuthnRequest(t, sampleAuthnRequestXML("https://iam.example.test/saml/idp/sso")),
	})
	if err != nil {
		t.Fatalf("complete sp initiated sso: %v", err)
	}

	responseXML := mustDecodeSAMLResponse(t, result.SAMLResponse)
	if !strings.Contains(responseXML, "<ds:Signature") {
		t.Fatalf("expected response signature in xml: %s", responseXML)
	}
}

func TestCompleteSPInitiatedRejectsDestinationMismatch(t *testing.T) {
	appID := uuid.New()
	tenantID := uuid.New()
	appRepo := stubApplicationRepository{
		app: appsdomain.Application{
			ID:       appID,
			TenantID: tenantID,
			Type:     appsdomain.TypeSAMLSP,
			Status:   appsdomain.StatusActive,
		},
	}
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:                appID,
		EntityID:             "https://sp.example.test/metadata",
		ACSURL:               "https://sp.example.test/saml/acs",
		WantAssertionsSigned: true,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, stubUserRepository{}, repo, newTestKeyManager(t), "test-session-secret", nil)
	_, err := svc.CompleteSPInitiated(context.Background(), authdomain.Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, samldomain.SPInitiatedRequest{
		Binding:     samldomain.BindingHTTPRedirect,
		SAMLRequest: mustDeflatedAuthnRequest(t, sampleAuthnRequestXML("https://iam.example.test/saml/idp/sso?wrong=1")),
	})
	if err == nil {
		t.Fatal("expected ACS validation error")
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

type stubUserRepository struct {
	user   userdomain.User
	err    error
	groups []string
}

func (s stubUserRepository) GetByID(ctx context.Context, id uuid.UUID) (userdomain.User, error) {
	if s.err != nil {
		return userdomain.User{}, s.err
	}
	if s.user.ID != id {
		return userdomain.User{}, store.ErrNotFound
	}
	return s.user, nil
}

func (s stubUserRepository) ListGroupCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if s.user.ID != userID {
		return nil, store.ErrNotFound
	}
	return append([]string(nil), s.groups...), nil
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

func (s *stubServiceProviderRepository) GetByEntityID(ctx context.Context, entityID string) (samldomain.ServiceProvider, error) {
	for _, item := range s.items {
		if item.EntityID == entityID {
			return item, nil
		}
	}
	return samldomain.ServiceProvider{}, store.ErrNotFound
}

func (s *stubServiceProviderRepository) Upsert(ctx context.Context, sp samldomain.ServiceProvider) (samldomain.ServiceProvider, error) {
	s.items[sp.AppID] = sp
	return sp, nil
}

type stubCertificateManager struct {
	metadataCertificate string
	certificate         *x509.Certificate
	privateKey          *rsa.PrivateKey
}

func (s stubCertificateManager) MetadataCertificate() string {
	return s.metadataCertificate
}

func (s stubCertificateManager) Certificate() *x509.Certificate {
	return s.certificate
}

func (s stubCertificateManager) PrivateKey() *rsa.PrivateKey {
	return s.privateKey
}

func authTestUser(id, tenantID uuid.UUID) userdomain.User {
	return userdomain.User{
		ID:          id,
		TenantID:    tenantID,
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		Status:      "active",
		Source:      "local",
	}
}

func newTestKeyManager(t *testing.T) *samlkeys.Manager {
	t.Helper()

	manager, err := samlkeys.NewManager("https://iam.example.test/saml/idp/metadata", "", "", nil)
	if err != nil {
		t.Fatalf("create test key manager: %v", err)
	}

	return manager
}

func mustDeflatedAuthnRequest(t *testing.T, rawXML string) string {
	t.Helper()

	var buffer bytes.Buffer
	writer, err := flate.NewWriter(&buffer, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("create flate writer: %v", err)
	}
	if _, err := writer.Write([]byte(rawXML)); err != nil {
		t.Fatalf("write authn request: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close flate writer: %v", err)
	}

	return base64.StdEncoding.EncodeToString(buffer.Bytes())
}

func mustDecodeSAMLResponse(t *testing.T, raw string) string {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode saml response: %v", err)
	}

	return string(decoded)
}

func mustFindElement(t *testing.T, rawXML string, tag string) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	if err := doc.ReadFromString(rawXML); err != nil {
		t.Fatalf("parse xml: %v", err)
	}

	var walk func(element *etree.Element) *etree.Element
	walk = func(element *etree.Element) *etree.Element {
		if element == nil {
			return nil
		}
		if element.Tag == tag {
			return element
		}
		for _, child := range element.ChildElements() {
			if found := walk(child); found != nil {
				return found
			}
		}
		return nil
	}

	found := walk(doc.Root())
	if found == nil {
		t.Fatalf("tag %q not found in xml: %s", tag, rawXML)
	}

	return found
}

func validateSignature(t *testing.T, element *etree.Element, certificate *x509.Certificate) {
	t.Helper()

	store := &goxmldsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{certificate},
	}
	ctx := goxmldsig.NewDefaultValidationContext(store)
	if _, err := ctx.Validate(element); err != nil {
		t.Fatalf("validate signature: %v", err)
	}
}

func sampleAuthnRequestXML(destination string) string {
	return `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_authn123" Version="2.0" IssueInstant="2026-03-25T10:00:00Z" Destination="` + destination + `" AssertionConsumerServiceURL="https://sp.example.test/saml/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.test/metadata</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>
</samlp:AuthnRequest>`
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
