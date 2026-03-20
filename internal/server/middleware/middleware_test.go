package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/miloyuans/openauthing/internal/logging"
)

func TestRecoveryReturnsUnifiedErrorResponse(t *testing.T) {
	var logs bytes.Buffer
	logger, err := logging.NewWithWriter("debug", &logs)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	router := chi.NewRouter()
	router.Use(RequestID)
	router.Use(Recovery(logger))
	router.Get("/panic", func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}

	var payload struct {
		RequestID string `json:"request_id"`
		Error     struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Error.Code != "internal_error" {
		t.Fatalf("expected internal_error, got %q", payload.Error.Code)
	}

	if payload.RequestID == "" {
		t.Fatal("expected request_id in recovery response")
	}
}

func TestLoggingIncludesRequestIDMethodPathStatusAndLatency(t *testing.T) {
	var logs bytes.Buffer
	logger, err := logging.NewWithWriter("debug", &logs)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	router := chi.NewRouter()
	router.Use(RequestID)
	router.Use(Logging(logger))
	router.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	logOutput := logs.String()
	for _, expected := range []string{
		`"request_id"`,
		`"method":"GET"`,
		`"path":"/ping"`,
		`"status":204`,
		`"latency_ms"`,
	} {
		if !strings.Contains(logOutput, expected) {
			t.Fatalf("expected log output to contain %s, got %s", expected, logOutput)
		}
	}
}
