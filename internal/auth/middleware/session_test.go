package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	"github.com/miloyuans/openauthing/internal/auth/sessionctx"
)

type authenticatorStub struct {
	session authdomain.Session
	err     error
}

func (s authenticatorStub) Authenticate(context.Context, string) (authdomain.Session, error) {
	return s.session, s.err
}

func TestRequireSessionAddsSessionToContext(t *testing.T) {
	mw := RequireSession("openauthing_session", authenticatorStub{
		session: authdomain.Session{
			ID:     uuid.New(),
			UserID: uuid.New(),
		},
	})

	next := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := sessionctx.FromContext(r.Context())
		if !ok || session.ID == uuid.Nil {
			t.Fatal("expected session in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "openauthing_session", Value: "raw-sid"})
	rec := httptest.NewRecorder()

	next.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

func TestRequireSessionRejectsMissingCookie(t *testing.T) {
	mw := RequireSession("openauthing_session", authenticatorStub{})
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called without cookie")
	}))

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()

	next.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error.Code != "unauthorized" {
		t.Fatalf("expected unauthorized error, got %#v", payload)
	}
}
