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

type GroupService interface {
	List(ctx context.Context, filter domain.GroupListFilter) ([]domain.Group, error)
	Create(ctx context.Context, input domain.CreateGroupInput) (domain.Group, error)
}

type GroupHandler struct {
	service GroupService
}

type groupListResponse struct {
	Items  []domain.Group `json:"items"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

func NewGroupHandler(service GroupService) *GroupHandler {
	return &GroupHandler{service: service}
}

func (h *GroupHandler) Register(r chi.Router) {
	r.Get("/groups", h.handleList)
	r.Post("/groups", h.handleCreate)
}

func (h *GroupHandler) handleList(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := httpinput.ParsePagination(r)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	filter := domain.GroupListFilter{
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

	_ = httpjson.Write(w, r, http.StatusOK, groupListResponse{Items: items, Limit: limit, Offset: offset})
}

func (h *GroupHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateGroupInput
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
