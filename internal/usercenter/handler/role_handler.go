package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/httpinput"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type RoleService interface {
	List(ctx context.Context, filter domain.RoleListFilter) ([]domain.Role, error)
	Create(ctx context.Context, input domain.CreateRoleInput) (domain.Role, error)
}

type RoleHandler struct {
	service RoleService
}

type roleListResponse struct {
	Items  []domain.Role `json:"items"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func NewRoleHandler(service RoleService) *RoleHandler {
	return &RoleHandler{service: service}
}

func (h *RoleHandler) Register(r chi.Router) {
	r.Get("/roles", h.handleList)
	r.Post("/roles", h.handleCreate)
}

func (h *RoleHandler) handleList(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := httpinput.ParsePagination(r)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	filter := domain.RoleListFilter{
		Name:   r.URL.Query().Get("name"),
		Code:   r.URL.Query().Get("code"),
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

	_ = httpjson.Write(w, r, http.StatusOK, roleListResponse{Items: items, Limit: limit, Offset: offset})
}

func (h *RoleHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateRoleInput
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
