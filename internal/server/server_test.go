package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miloyuans/openauthing/internal/config"
	"github.com/miloyuans/openauthing/internal/logging"
)

type responseEnvelope struct {
	RequestID string `json:"request_id"`
	Data      struct {
		Service string          `json:"service"`
		Status  string          `json:"status"`
		Checks  map[string]bool `json:"checks"`
		Message string          `json:"message"`
	} `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()

	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	return New(cfg, logger)
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, config.Config{
		App: config.AppConfig{Name: "openauthing", Env: "test"},
		HTTP: config.HTTPConfig{
			Addr:           ":0",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Postgres: config.PostgresConfig{DSN: "postgres://configured"},
		Redis:    config.RedisConfig{Addr: "redis:6379"},
		Log:      config.LogConfig{Level: "debug"},
		Session:  config.SessionConfig{Secret: "test-session-secret"},
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload responseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid json response: %v", err)
	}

	if payload.Data.Service != "openauthing" {
		t.Fatalf("expected service openauthing, got %q", payload.Data.Service)
	}

	if payload.Data.Status != "ok" {
		t.Fatalf("expected status ok, got %q", payload.Data.Status)
	}

	if payload.RequestID == "" {
		t.Fatal("expected request_id in response body")
	}

	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID header")
	}

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("expected cors header to be set, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestReadyz(t *testing.T) {
	srv := newTestServer(t, config.Config{
		App: config.AppConfig{Name: "openauthing", Env: "test"},
		HTTP: config.HTTPConfig{
			Addr:           ":0",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Postgres: config.PostgresConfig{DSN: "postgres://configured"},
		Redis:    config.RedisConfig{Addr: "redis:6379"},
		Log:      config.LogConfig{Level: "debug"},
		Session:  config.SessionConfig{Secret: "test-session-secret"},
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload responseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid json response: %v", err)
	}

	if payload.Data.Status != "ready" {
		t.Fatalf("expected ready status, got %q", payload.Data.Status)
	}

	if !payload.Data.Checks["postgres_configured"] || !payload.Data.Checks["redis_configured"] {
		t.Fatalf("expected readiness checks to pass, got %#v", payload.Data.Checks)
	}
}

func TestReadyzReturns503WhenDependenciesMissing(t *testing.T) {
	srv := newTestServer(t, config.Config{
		App: config.AppConfig{Name: "openauthing", Env: "test"},
		HTTP: config.HTTPConfig{
			Addr:           ":0",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Log:     config.LogConfig{Level: "debug"},
		Session: config.SessionConfig{Secret: "test-session-secret"},
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var payload responseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid json response: %v", err)
	}

	if payload.Error == nil {
		t.Fatal("expected error payload")
	}

	if payload.Error.Code != "service_not_ready" {
		t.Fatalf("expected service_not_ready error, got %q", payload.Error.Code)
	}
}

func TestPingReturnsUnifiedSuccessResponse(t *testing.T) {
	srv := newTestServer(t, config.Config{
		App: config.AppConfig{Name: "openauthing", Env: "test"},
		HTTP: config.HTTPConfig{
			Addr:           ":0",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Postgres: config.PostgresConfig{DSN: "postgres://configured"},
		Redis:    config.RedisConfig{Addr: "redis:6379"},
		Log:      config.LogConfig{Level: "debug"},
		Session:  config.SessionConfig{Secret: "test-session-secret"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload responseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid json response: %v", err)
	}

	if payload.Data.Message != "pong" {
		t.Fatalf("expected pong response, got %#v", payload.Data)
	}

	if payload.RequestID == "" {
		t.Fatal("expected request_id in ping response")
	}
}
