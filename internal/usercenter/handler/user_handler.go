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

type UserService interface {
	List(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error)
	Create(ctx context.Context, input domain.CreateUserInput) (domain.User, error)
	GetByID(ctx context.Context, id string) (domain.User, error)
	Update(ctx context.Context, id string, input domain.UpdateUserInput) (domain.User, error)
}

type UserHandler struct {
	service UserService
}

type userListResponse struct {
	Items  []domain.User `json:"items"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func NewUserHandler(service UserService) *UserHandler {
	return &UserHandler{service: service}
}

func (h *UserHandler) Register(r chi.Router) {
	r.Get("/users", h.handleList)
	r.Post("/users", h.handleCreate)
	r.Get("/users/{id}", h.handleGetByID)
	r.Put("/users/{id}", h.handleUpdate)
}

func (h *UserHandler) handleList(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := httpinput.ParsePagination(r)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	filter := domain.UserListFilter{
		Username: r.URL.Query().Get("username"),
		Email:    r.URL.Query().Get("email"),
		Status:   r.URL.Query().Get("status"),
		Limit:    limit,
		Offset:   offset,
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

	_ = httpjson.Write(w, r, http.StatusOK, userListResponse{
		Items:  items,
		Limit:  limit,
		Offset: offset,
	})
}

func (h *UserHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateUserInput
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

func (h *UserHandler) handleGetByID(w http.ResponseWriter, r *http.Request) {
	user, err := h.service.GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, user)
}

func (h *UserHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var input domain.UpdateUserInput
	if err := httpinput.DecodeJSON(r, &input); err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	updated, err := h.service.Update(r.Context(), chi.URLParam(r, "id"), input)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, updated)
}
