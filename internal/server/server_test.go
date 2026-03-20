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

type discoveryDocument struct {
	Issuer    string   `json:"issuer"`
	JWKSURI   string   `json:"jwks_uri"`
	Responses []string `json:"response_types_supported"`
	Scopes    []string `json:"scopes_supported"`
}

type jwksDocument struct {
	Keys []struct {
		KTY string `json:"kty"`
		Alg string `json:"alg"`
		KID string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func newTestServer(t *testing.T, cfg config.Config) *Server {
	t.Helper()

	logger, err := logging.NewWithWriter("debug", io.Discard)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	srv, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	return srv
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, config.Config{
		App: config.AppConfig{Name: "openauthing", Env: "test"},
		HTTP: config.HTTPConfig{
			Addr:           ":0",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Postgres: config.PostgresConfig{DSN: "postgres://openauthing@localhost:5432/openauthing?sslmode=disable"},
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
		Postgres: config.PostgresConfig{DSN: "postgres://openauthing@localhost:5432/openauthing?sslmode=disable"},
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
		Postgres: config.PostgresConfig{DSN: "postgres://openauthing@localhost:5432/openauthing?sslmode=disable"},
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
		Postgres: config.PostgresConfig{DSN: "postgres://openauthing@localhost:5432/openauthing?sslmode=disable"},
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

func TestOIDCDiscoveryEndpoint(t *testing.T) {
	srv := newTestServer(t, config.Config{
		App: config.AppConfig{Name: "openauthing", Env: "test"},
		HTTP: config.HTTPConfig{
			Addr:           ":0",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Postgres: config.PostgresConfig{DSN: "postgres://openauthing@localhost:5432/openauthing?sslmode=disable"},
		Redis:    config.RedisConfig{Addr: "redis:6379"},
		Log:      config.LogConfig{Level: "debug"},
		Session:  config.SessionConfig{Secret: "test-session-secret"},
		OIDC:     config.OIDCConfig{Issuer: "https://iam.example.test"},
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload discoveryDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid discovery response: %v", err)
	}

	if payload.Issuer != "https://iam.example.test" {
		t.Fatalf("expected issuer to match config, got %q", payload.Issuer)
	}

	if payload.JWKSURI != "https://iam.example.test/.well-known/jwks.json" {
		t.Fatalf("expected jwks_uri, got %q", payload.JWKSURI)
	}

	if len(payload.Responses) == 0 || payload.Responses[0] != "code" {
		t.Fatalf("expected response types to contain code, got %#v", payload.Responses)
	}
}

func TestOIDCJWKSEndpoint(t *testing.T) {
	srv := newTestServer(t, config.Config{
		App: config.AppConfig{Name: "openauthing", Env: "test"},
		HTTP: config.HTTPConfig{
			Addr:           ":0",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Postgres: config.PostgresConfig{DSN: "postgres://openauthing@localhost:5432/openauthing?sslmode=disable"},
		Redis:    config.RedisConfig{Addr: "redis:6379"},
		Log:      config.LogConfig{Level: "debug"},
		Session:  config.SessionConfig{Secret: "test-session-secret"},
		OIDC:     config.OIDCConfig{Issuer: "https://iam.example.test"},
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload jwksDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid jwks response: %v", err)
	}

	if len(payload.Keys) != 1 {
		t.Fatalf("expected one jwk, got %d", len(payload.Keys))
	}

	if payload.Keys[0].KTY != "RSA" || payload.Keys[0].Alg != "RS256" || payload.Keys[0].KID == "" || payload.Keys[0].N == "" || payload.Keys[0].E == "" {
		t.Fatalf("unexpected jwk payload: %#v", payload.Keys[0])
	}
}
