package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/apps/domain"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/httpinput"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
)

type ApplicationService interface {
	List(ctx context.Context, filter domain.ApplicationListFilter) ([]domain.Application, error)
	Create(ctx context.Context, input domain.CreateApplicationInput) (domain.Application, error)
}

type ApplicationHandler struct {
	service ApplicationService
}

type applicationListResponse struct {
	Items  []domain.Application `json:"items"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

func NewApplicationHandler(service ApplicationService) *ApplicationHandler {
	return &ApplicationHandler{service: service}
}

func (h *ApplicationHandler) Register(r chi.Router) {
	r.Get("/apps", h.handleList)
	r.Post("/apps", h.handleCreate)
}

func (h *ApplicationHandler) handleList(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := httpinput.ParsePagination(r)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	filter := domain.ApplicationListFilter{
		Name:   r.URL.Query().Get("name"),
		Code:   r.URL.Query().Get("code"),
		Type:   r.URL.Query().Get("type"),
		Status: r.URL.Query().Get("status"),
		Limit:  limit,
		Offset: offset,
	}

	if rawTenantID := r.URL.Query().Get("tenant_id"); rawTenantID != "" {
		tenantID, parseErr := uuid.Parse(rawTenantID)
		if parseErr != nil {
			_ = httpjson.WriteAPIError(w, r, apierror.Validation(map[string]any{
				"fields": map[string]string{"tenant_id": "must be a valid UUID"},
			}))
			return
		}
		filter.TenantID = &tenantID
	}

	items, err := h.service.List(r.Context(), filter)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, applicationListResponse{Items: items, Limit: limit, Offset: offset})
}

func (h *ApplicationHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateApplicationInput
	if err := httpinput.DecodeJSON(r, &input); err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	created, err := h.service.Create(r.Context(), input)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusCreated, created)
}
