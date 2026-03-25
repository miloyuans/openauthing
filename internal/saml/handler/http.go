package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	"github.com/miloyuans/openauthing/internal/shared/httpinput"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
)

type Service interface {
	GetByAppID(ctx context.Context, rawAppID string) (samldomain.ServiceProvider, error)
	Upsert(ctx context.Context, rawAppID string, input samldomain.UpsertServiceProviderInput) (samldomain.ServiceProvider, error)
	ImportMetadata(ctx context.Context, rawAppID, metadataXML string) (samldomain.ServiceProvider, error)
	IDPMetadata() ([]byte, error)
	CompleteSPInitiated(ctx context.Context, session authdomain.Session, input samldomain.SPInitiatedRequest) (samldomain.LoginResult, error)
	CompleteIDPInitiated(ctx context.Context, session authdomain.Session, rawAppID, rawEntityID string) (samldomain.LoginResult, error)
}

type SessionAuthenticator interface {
	Authenticate(ctx context.Context, sid string) (authdomain.Session, error)
}

type Handler struct {
	service       Service
	cookieName    string
	authenticator SessionAuthenticator
}

type importMetadataRequest struct {
	MetadataXML string `json:"metadata_xml"`
}

func NewHandler(service Service, cookieName string, authenticator SessionAuthenticator) *Handler {
	if strings.TrimSpace(cookieName) == "" {
		cookieName = "openauthing_session"
	}

	return &Handler{
		service:       service,
		cookieName:    cookieName,
		authenticator: authenticator,
	}
}

func (h *Handler) RegisterAPI(r chi.Router) {
	r.Get("/apps/{id}/saml", h.handleGetServiceProvider)
	r.Put("/apps/{id}/saml", h.handleUpsertServiceProvider)
	r.Post("/apps/{id}/saml/import-metadata", h.handleImportMetadata)
}

func (h *Handler) RegisterPublic(r chi.Router) {
	r.Get("/saml/idp/metadata", h.handleIDPMetadata)
	r.Get("/saml/idp/login", h.handleLoginPage)
	r.Get("/saml/idp/sso", h.handleSSO)
	r.Post("/saml/idp/sso", h.handleSSO)
}

func (h *Handler) handleGetServiceProvider(w http.ResponseWriter, r *http.Request) {
	result, err := h.service.GetByAppID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, result)
}

func (h *Handler) handleUpsertServiceProvider(w http.ResponseWriter, r *http.Request) {
	var input samldomain.UpsertServiceProviderInput
	if err := httpinput.DecodeJSON(r, &input); err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	result, err := h.service.Upsert(r.Context(), chi.URLParam(r, "id"), input)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, result)
}

func (h *Handler) handleImportMetadata(w http.ResponseWriter, r *http.Request) {
	var input importMetadataRequest
	if err := httpinput.DecodeJSON(r, &input); err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	result, err := h.service.ImportMetadata(r.Context(), chi.URLParam(r, "id"), input.MetadataXML)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, result)
}

func (h *Handler) handleIDPMetadata(w http.ResponseWriter, r *http.Request) {
	body, err := h.service.IDPMetadata()
	if err != nil {
		http.Error(w, "failed to generate SAML metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
