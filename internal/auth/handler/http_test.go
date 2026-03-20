package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	"github.com/miloyuans/openauthing/internal/auth/sessionctx"
)

type authServiceStub struct{}

func (authServiceStub) Login(_ context.Context, input authdomain.LoginInput, _ authdomain.RequestMeta) (authdomain.LoginResult, error) {
	return authdomain.LoginResult{
		Authenticated: true,
		User: authdomain.UserSummary{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Username:    input.Username,
			Email:       input.Email,
			DisplayName: "Alice",
			Status:      "active",
			Source:      "local",
		},
		SessionID: "raw-session-id",
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func (authServiceStub) Me(context.Context, authdomain.Session) (authdomain.UserSummary, error) {
	return authdomain.UserSummary{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Username:    "alice",
		DisplayName: "Alice",
		Status:      "active",
		Source:      "local",
	}, nil
}

func (authServiceStub) LogoutCurrent(context.Context, authdomain.Session) error {
	return nil
}

func (authServiceStub) ListSessions(context.Context, authdomain.Session) ([]authdomain.SessionListItem, error) {
	return []authdomain.SessionListItem{{
		ID:      uuid.New(),
		Status:  authdomain.SessionStatusActive,
		Current: true,
	}}, nil
}

func (authServiceStub) RevokeSession(context.Context, authdomain.Session, string) error {
	return nil
}

func TestHandleLoginSetsCookie(t *testing.T) {
	handler := NewHandler(authServiceStub{}, DefaultCookieName, false, nil)
	router := chi.NewRouter()
	handler.Register(router)

	rawBody, err := json.Marshal(map[string]any{
		"username": "alice",
		"password": "secret123",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != DefaultCookieName || cookies[0].HttpOnly == false {
		t.Fatalf("expected session cookie, got %#v", cookies)
	}
}

func TestHandleMe(t *testing.T) {
	sessionMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(sessionctx.NewContext(r.Context(), authdomain.Session{
				ID:     uuid.New(),
				UserID: uuid.New(),
			})))
		})
	}

	handler := NewHandler(authServiceStub{}, DefaultCookieName, false, sessionMiddleware)
	router := chi.NewRouter()
	handler.Register(router)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload struct {
		Data struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Data.Username != "alice" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}
