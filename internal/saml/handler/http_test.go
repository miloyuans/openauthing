package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
)

func TestMetadataEndpointReturnsXML(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(stubService{
		metadata: []byte(`<?xml version="1.0"?><EntityDescriptor entityID="https://iam.example.test/saml/idp/metadata"></EntityDescriptor>`),
	}).RegisterPublic(router)

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
	}).RegisterAPI(router)

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

type stubService struct {
	item     samldomain.ServiceProvider
	imported samldomain.ServiceProvider
	metadata []byte
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
