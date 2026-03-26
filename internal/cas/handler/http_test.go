package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	casdomain "github.com/miloyuans/openauthing/internal/cas/domain"
)

type stubService struct {
	normalizedService string
	loginTicket       string
	loginErr          error
	validateResult    casdomain.ValidationResult
	validateErr       error
	serviceXML        []byte
	failureXML        []byte
}

func (s stubService) NormalizeService(rawService string) (string, error) {
	if s.normalizedService != "" {
		return s.normalizedService, nil
	}
	return rawService, nil
}

func (s stubService) Login(ctx context.Context, session authdomain.Session, rawService string) (string, error) {
	return s.loginTicket, s.loginErr
}

func (s stubService) ValidateServiceTicket(ctx context.Context, rawService, rawTicket string, withAttributes bool) (casdomain.ValidationResult, error) {
	return s.validateResult, s.validateErr
}

func (s stubService) ServiceResponseXML(result casdomain.ValidationResult, withAttributes bool) ([]byte, error) {
	return s.serviceXML, nil
}

func (s stubService) FailureResponseXML(code, message string) ([]byte, error) {
	return s.failureXML, nil
}

type stubAuthenticator struct {
	session authdomain.Session
	err     error
}

func (s stubAuthenticator) Authenticate(ctx context.Context, sid string) (authdomain.Session, error) {
	if s.err != nil {
		return authdomain.Session{}, s.err
	}
	return s.session, nil
}

func TestLoginRedirectsAuthenticatedUserWithServiceTicket(t *testing.T) {
	router := chi.NewRouter()
	service := stubService{
		normalizedService: "https://service.example.test/app?target=home",
		loginTicket:       "ST-raw-ticket",
	}
	handler := NewHandler(service, "openauthing_session", stubAuthenticator{
		session: authdomain.Session{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
	})
	handler.Register(router)

	req := httptest.NewRequest(http.MethodGet, "/cas/login?service=https%3A%2F%2Fservice.example.test%2Fapp%3Ftarget%3Dhome", nil)
	req.AddCookie(&http.Cookie{Name: "openauthing_session", Value: "sid-123"})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "https://service.example.test/app?target=home&ticket=ST-raw-ticket" {
		t.Fatalf("unexpected redirect location: %q", location)
	}
}

func TestLoginRendersHTMLWhenNoSession(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(stubService{}, "openauthing_session", nil).Register(router)

	req := httptest.NewRequest(http.MethodGet, "/cas/login?service=https%3A%2F%2Fservice.example.test%2Fapp", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "continue the CAS login flow") {
		t.Fatalf("expected CAS login page, got %s", rec.Body.String())
	}
}

func TestP3ServiceValidateReturnsXML(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(stubService{
		serviceXML: []byte(`<?xml version="1.0"?><cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>alice</cas:user><cas:attributes><cas:email>alice@example.com</cas:email></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>`),
	}, "openauthing_session", nil).Register(router)

	req := httptest.NewRequest(http.MethodGet, "/cas/p3/serviceValidate?service=https%3A%2F%2Fservice.example.test%2Fapp&ticket=ST-raw-ticket", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/xml; charset=utf-8" {
		t.Fatalf("unexpected content type: %q", contentType)
	}
	if !strings.Contains(rec.Body.String(), "<cas:email>alice@example.com</cas:email>") {
		t.Fatalf("expected CAS attributes in response, got %s", rec.Body.String())
	}
}
