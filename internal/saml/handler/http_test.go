package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
)

func TestMetadataEndpointReturnsXML(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(stubService{
		metadata: []byte(`<?xml version="1.0"?><EntityDescriptor entityID="https://iam.example.test/saml/idp/metadata"></EntityDescriptor>`),
	}, "openauthing_session", nil).RegisterPublic(router)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/metadata", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if contentType := rec.Header().Get("Content-Type"); contentType != "application/samlmetadata+xml; charset=utf-8" {
		t.Fatalf("unexpected content type: %q", contentType)
	}
}

func TestImportMetadataEndpointReturnsUnifiedJSON(t *testing.T) {
	appID := uuid.New()
	router := chi.NewRouter()
	NewHandler(stubService{
		imported: samldomain.ServiceProvider{
			AppID:    appID,
			EntityID: "https://sp.example.test/metadata",
			ACSURL:   "https://sp.example.test/saml/acs",
		},
	}, "openauthing_session", nil).RegisterAPI(router)

	body := map[string]any{
		"metadata_xml": "<EntityDescriptor entityID=\"https://sp.example.test/metadata\"></EntityDescriptor>",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/apps/"+appID.String()+"/saml/import-metadata", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var response struct {
		Data struct {
			EntityID string `json:"entity_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Data.EntityID != "https://sp.example.test/metadata" {
		t.Fatalf("unexpected response payload: %#v", response.Data)
	}
}

func TestSSORedirectsToLoginWhenNoSession(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(stubService{}, "openauthing_session", nil).RegisterPublic(router)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/sso?SAMLRequest=abc123", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/saml/idp/login?continue=") {
		t.Fatalf("unexpected redirect location: %q", location)
	}
}

func TestLoginPageRendersHTML(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(stubService{}, "openauthing_session", nil).RegisterPublic(router)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/login?continue=%2Fsaml%2Fidp%2Fsso%3FSAMLRequest%3Dabc123", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "Use your openauthing account") {
		t.Fatalf("expected login page content, got %s", rec.Body.String())
	}
}

func TestLoginPageWithSessionReturnsAutoPostForm(t *testing.T) {
	router := chi.NewRouter()
	service := stubService{
		idpResult: samldomain.LoginResult{
			ACSURL:       "https://sp.example.test/saml/acs",
			SAMLResponse: "PHNhbWxwOlJlc3BvbnNlLz4=",
		},
	}
	handler := NewHandler(service, "openauthing_session", stubAuthenticator{
		session: authdomain.Session{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			UserID:    uuid.New(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
	})
	handler.RegisterPublic(router)

	req := httptest.NewRequest(http.MethodGet, "/saml/idp/login?app_id="+uuid.NewString(), nil)
	req.AddCookie(&http.Cookie{Name: "openauthing_session", Value: "sid-123"})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `action="https://sp.example.test/saml/acs"`) {
		t.Fatalf("expected ACS form action, got %s", body)
	}
	if !strings.Contains(body, `name="SAMLResponse"`) {
		t.Fatalf("expected SAMLResponse form field, got %s", body)
	}
}

type stubService struct {
	item     samldomain.ServiceProvider
	imported samldomain.ServiceProvider
	metadata []byte
	ssoResult samldomain.LoginResult
	idpResult samldomain.LoginResult
}

func (s stubService) GetByAppID(ctx context.Context, rawAppID string) (samldomain.ServiceProvider, error) {
	return s.item, nil
}

func (s stubService) Upsert(ctx context.Context, rawAppID string, input samldomain.UpsertServiceProviderInput) (samldomain.ServiceProvider, error) {
	return s.item, nil
}

func (s stubService) ImportMetadata(ctx context.Context, rawAppID, metadataXML string) (samldomain.ServiceProvider, error) {
	return s.imported, nil
}

func (s stubService) IDPMetadata() ([]byte, error) {
	return s.metadata, nil
}

func (s stubService) CompleteSPInitiated(ctx context.Context, session authdomain.Session, input samldomain.SPInitiatedRequest) (samldomain.LoginResult, error) {
	return s.ssoResult, nil
}

func (s stubService) CompleteIDPInitiated(ctx context.Context, session authdomain.Session, rawAppID, rawEntityID string) (samldomain.LoginResult, error) {
	return s.idpResult, nil
}

type stubAuthenticator struct {
	session authdomain.Session
	err     error
}

func (s stubAuthenticator) Authenticate(ctx context.Context, sid string) (authdomain.Session, error) {
	if s.err != nil {
		return authdomain.Session{}, s.err
	}
	return s.session, nil
}
