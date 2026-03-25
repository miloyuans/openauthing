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
		nil,
		nil,
		stubCertificateManager{metadataCertificate: "BASE64CERT"},
		nil,
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
	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, nil, repo, nil, nil, stubCertificateManager{metadataCertificate: "BASE64CERT"}, nil, "test-secret", nil)

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

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, nil, repo, nil, nil, stubCertificateManager{metadataCertificate: "BASE64CERT"}, nil, "test-secret", nil)
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
	loginSessionRepo := newStubLoginSessionRepository()
	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, userRepo, repo, loginSessionRepo, nil, keyManager, nil, "test-session-secret", nil)
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

	if len(loginSessionRepo.items) != 1 {
		t.Fatalf("expected one saml login session binding, got %d", len(loginSessionRepo.items))
	}
	for _, item := range loginSessionRepo.items {
		if item.SessionIndex != item.SessionID.String() {
			t.Fatalf("expected session_index to match center session id, got %#v", item)
		}
		if item.NameID == "" {
			t.Fatalf("expected persisted name_id, got %#v", item)
		}
	}
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
	loginSessionRepo := newStubLoginSessionRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:                appID,
		EntityID:             "https://sp.example.test/metadata",
		ACSURL:               "https://sp.example.test/saml/acs",
		NameIDFormat:         samldomain.DefaultNameIDFormat,
		WantAssertionsSigned: true,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, userRepo, repo, loginSessionRepo, nil, newTestKeyManager(t), nil, "test-session-secret", nil)
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
	loginSessionRepo := newStubLoginSessionRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:                appID,
		EntityID:             "https://sp.example.test/metadata",
		ACSURL:               "https://sp.example.test/saml/acs",
		NameIDFormat:         samldomain.DefaultNameIDFormat,
		WantAssertionsSigned: true,
		WantResponseSigned:   true,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, userRepo, repo, loginSessionRepo, nil, newTestKeyManager(t), nil, "test-session-secret", nil)
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

func TestHandleLogoutRequestInvalidatesBoundSessionsAndCenterSession(t *testing.T) {
	appID := uuid.New()
	userID := uuid.New()
	sessionID := uuid.New()
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:    appID,
		EntityID: "https://sp.example.test/metadata",
		SLOURL:   "https://sp.example.test/saml/slo",
	}

	loginSessionRepo := newStubLoginSessionRepository()
	loginSessionRepo.items[uuid.New()] = samldomain.LoginSession{
		ID:           uuid.New(),
		AppID:        appID,
		UserID:       userID,
		SessionID:    sessionID,
		NameID:       "alice@example.com",
		SessionIndex: sessionID.String(),
		Status:       samldomain.LoginSessionStatusActive,
		IssuedAt:     time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC),
		ExpiresAt:    time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC),
	}
	centerSessions := &stubCenterSessionRepository{}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", nil, nil, repo, loginSessionRepo, centerSessions, newTestKeyManager(t), nil, "test-session-secret", nil)
	svc.now = func() time.Time { return time.Date(2026, 3, 25, 11, 0, 0, 0, time.UTC) }

	result, err := svc.HandleLogoutRequest(context.Background(), samldomain.LogoutRequest{
		Binding:     samldomain.BindingHTTPRedirect,
		SAMLRequest: mustDeflatedAuthnRequest(t, sampleLogoutRequestXML("https://iam.example.test/saml/idp/slo", sessionID.String(), "alice@example.com")),
		RelayState:  "relay-logout",
	})
	if err != nil {
		t.Fatalf("handle logout request: %v", err)
	}

	if result.SLOURL != "https://sp.example.test/saml/slo" {
		t.Fatalf("unexpected slo url: %#v", result)
	}
	if result.RelayState != "relay-logout" {
		t.Fatalf("unexpected relay state: %q", result.RelayState)
	}

	if len(centerSessions.loggedOut) != 1 || centerSessions.loggedOut[0] != sessionID {
		t.Fatalf("expected center session logout for %s, got %#v", sessionID, centerSessions.loggedOut)
	}

	logoutResponseXML := mustDecodeSAMLResponse(t, result.SAMLResponse)
	if !strings.Contains(logoutResponseXML, "LogoutResponse") || !strings.Contains(logoutResponseXML, `InResponseTo="_logout123"`) {
		t.Fatalf("expected logout response payload, got %s", logoutResponseXML)
	}

	for _, item := range loginSessionRepo.items {
		if item.SessionID == sessionID && item.Status != samldomain.LoginSessionStatusLoggedOut {
			t.Fatalf("expected bound saml session to be invalidated, got %#v", item)
		}
	}
}

func TestHandleLogoutRequestCanFindSessionByNameID(t *testing.T) {
	appID := uuid.New()
	sessionID := uuid.New()
	repo := newStubServiceProviderRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:    appID,
		EntityID: "https://sp.example.test/metadata",
		SLOURL:   "https://sp.example.test/saml/slo",
	}

	loginSessionRepo := newStubLoginSessionRepository()
	loginSessionRepo.items[uuid.New()] = samldomain.LoginSession{
		ID:           uuid.New(),
		AppID:        appID,
		UserID:       uuid.New(),
		SessionID:    sessionID,
		NameID:       "alice@example.com",
		SessionIndex: sessionID.String(),
		Status:       samldomain.LoginSessionStatusActive,
		IssuedAt:     time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC),
		ExpiresAt:    time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC),
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", nil, nil, repo, loginSessionRepo, &stubCenterSessionRepository{}, newTestKeyManager(t), nil, "test-session-secret", nil)
	svc.now = func() time.Time { return time.Date(2026, 3, 25, 11, 0, 0, 0, time.UTC) }

	_, err := svc.HandleLogoutRequest(context.Background(), samldomain.LogoutRequest{
		Binding:     samldomain.BindingHTTPRedirect,
		SAMLRequest: mustDeflatedAuthnRequest(t, sampleLogoutRequestWithoutSessionIndexXML("https://iam.example.test/saml/idp/slo", "alice@example.com")),
	})
	if err != nil {
		t.Fatalf("handle logout request by name_id: %v", err)
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
	loginSessionRepo := newStubLoginSessionRepository()
	repo.items[appID] = samldomain.ServiceProvider{
		AppID:                appID,
		EntityID:             "https://sp.example.test/metadata",
		ACSURL:               "https://sp.example.test/saml/acs",
		WantAssertionsSigned: true,
	}

	svc := NewService(config.SAMLConfig{}, "https://iam.example.test", appRepo, stubUserRepository{}, repo, loginSessionRepo, nil, newTestKeyManager(t), nil, "test-session-secret", nil)
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

type stubLoginSessionRepository struct {
	items map[uuid.UUID]samldomain.LoginSession
}

func newStubLoginSessionRepository() *stubLoginSessionRepository {
	return &stubLoginSessionRepository{items: map[uuid.UUID]samldomain.LoginSession{}}
}

func (s *stubLoginSessionRepository) Upsert(ctx context.Context, session samldomain.LoginSession) (samldomain.LoginSession, error) {
	for id, item := range s.items {
		if item.AppID == session.AppID && item.SessionID == session.SessionID {
			session.ID = id
			session.CreatedAt = item.CreatedAt
			session.UpdatedAt = session.IssuedAt
			session.LogoutAt = nil
			s.items[id] = session
			return session, nil
		}
	}

	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = session.IssuedAt
	}
	session.UpdatedAt = session.IssuedAt
	s.items[session.ID] = session
	return session, nil
}

func (s *stubLoginSessionRepository) GetActiveByAppAndSessionIndex(ctx context.Context, appID uuid.UUID, sessionIndex string) (samldomain.LoginSession, error) {
	for _, item := range s.items {
		if item.AppID == appID && item.SessionIndex == sessionIndex && item.Status == samldomain.LoginSessionStatusActive {
			return item, nil
		}
	}
	return samldomain.LoginSession{}, store.ErrNotFound
}

func (s *stubLoginSessionRepository) GetActiveByAppAndNameID(ctx context.Context, appID uuid.UUID, nameID string) (samldomain.LoginSession, error) {
	for _, item := range s.items {
		if item.AppID == appID && item.NameID == nameID && item.Status == samldomain.LoginSessionStatusActive {
			return item, nil
		}
	}
	return samldomain.LoginSession{}, store.ErrNotFound
}

func (s *stubLoginSessionRepository) InvalidateBySessionID(ctx context.Context, sessionID uuid.UUID, logoutAt time.Time) error {
	found := false
	for id, item := range s.items {
		if item.SessionID == sessionID && item.Status == samldomain.LoginSessionStatusActive {
			item.Status = samldomain.LoginSessionStatusLoggedOut
			item.LogoutAt = &logoutAt
			item.UpdatedAt = logoutAt
			s.items[id] = item
			found = true
		}
	}
	if !found {
		return store.ErrNotFound
	}
	return nil
}

type stubCenterSessionRepository struct {
	loggedOut []uuid.UUID
}

func (s *stubCenterSessionRepository) Logout(ctx context.Context, id uuid.UUID, logoutAt time.Time) error {
	s.loggedOut = append(s.loggedOut, id)
	return nil
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

func sampleLogoutRequestXML(destination, sessionIndex, nameID string) string {
	return `<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout123" Version="2.0" IssueInstant="2026-03-25T11:00:00Z" Destination="` + destination + `">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.test/metadata</saml:Issuer>
  <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + nameID + `</saml:NameID>
  <samlp:SessionIndex>` + sessionIndex + `</samlp:SessionIndex>
</samlp:LogoutRequest>`
}

func sampleLogoutRequestWithoutSessionIndexXML(destination, nameID string) string {
	return `<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout123" Version="2.0" IssueInstant="2026-03-25T11:00:00Z" Destination="` + destination + `">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.test/metadata</saml:Issuer>
  <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + nameID + `</saml:NameID>
</samlp:LogoutRequest>`
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
