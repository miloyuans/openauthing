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
	"github.com/miloyuans/openauthing/internal/usercenter/domain"
)

type userServiceStub struct{}

func (userServiceStub) List(context.Context, domain.UserListFilter) ([]domain.User, error) {
	return nil, nil
}

func (userServiceStub) Create(_ context.Context, input domain.CreateUserInput) (domain.User, error) {
	return domain.User{
		ID:           uuid.New(),
		TenantID:     input.TenantID,
		Username:     input.Username,
		Email:        input.Email,
		DisplayName:  input.DisplayName,
		PasswordHash: "hashed-secret",
		Status:       "active",
		Source:       "local",
	}, nil
}

func (userServiceStub) GetByID(context.Context, string) (domain.User, error) {
	return domain.User{}, nil
}

func (userServiceStub) Update(context.Context, string, domain.UpdateUserInput) (domain.User, error) {
	return domain.User{}, nil
}

func TestUserHandlerCreate(t *testing.T) {
	handler := NewUserHandler(userServiceStub{})
	router := chi.NewRouter()
	handler.Register(router)

	body := map[string]any{
		"tenant_id":    uuid.NewString(),
		"username":     "alice",
		"display_name": "Alice",
		"email":        "alice@example.com",
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var response struct {
		RequestID string `json:"request_id"`
		Data      struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Data.Username != "alice" {
		t.Fatalf("unexpected username: %#v", response.Data)
	}

	if bytes.Contains(rec.Body.Bytes(), []byte("password_hash")) {
		t.Fatal("expected password_hash to be omitted from response")
	}
}
