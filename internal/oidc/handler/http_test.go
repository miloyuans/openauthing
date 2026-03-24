package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	oidcdomain "github.com/miloyuans/openauthing/internal/oidc/domain"
)

func TestDiscoveryEndpointReturnsOIDCMetadata(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(&stubOIDCService{
		discovery: oidcdomain.DiscoveryDocument{
			Issuer:   "https://iam.example.test",
			JWKSURI:  "https://iam.example.test/.well-known/jwks.json",
			ScopesSupported: []string{"openid"},
		},
	}, "").Register(router)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode discovery payload: %v", err)
	}

	if payload["issuer"] != "https://iam.example.test" {
		t.Fatalf("expected issuer, got %#v", payload["issuer"])
	}
}

func TestJWKSEndpointReturnsRSAKeySet(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(&stubOIDCService{
		jwks: oidcdomain.JWKSet{
			Keys: []oidcdomain.JWK{{
				KTY: "RSA",
				Alg: "RS256",
				KID: "kid-1",
				N:   "n-value",
				E:   "AQAB",
			}},
		},
	}, "").Register(router)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload struct {
		Keys []struct {
			KTY string `json:"kty"`
			Alg string `json:"alg"`
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode jwks payload: %v", err)
	}

	if len(payload.Keys) != 1 || payload.Keys[0].KTY != "RSA" || payload.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected jwks payload: %#v", payload.Keys)
	}
}

func TestAuthorizeRedirectsToClientCallback(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(&stubOIDCService{
		authorizeResult: oidcdomain.AuthorizationResult{
			RedirectURI: "https://client.example.test/callback",
			Code:        "code-123",
			State:       "state-1",
		},
	}, defaultSessionCookieName).Register(router)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=client&redirect_uri=https://client.example.test/callback&scope=openid&state=state-1", nil)
	req.AddCookie(&http.Cookie{Name: defaultSessionCookieName, Value: "session-cookie"})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.Contains(location, "code=code-123") || !strings.Contains(location, "state=state-1") {
		t.Fatalf("expected redirect location to include code and state, got %q", location)
	}
}

func TestTokenEndpointReturnsOAuthJSON(t *testing.T) {
	router := chi.NewRouter()
	service := &stubOIDCService{
		tokenResponse: oidcdomain.TokenResponse{
			AccessToken:  "access.jwt",
			TokenType:    "Bearer",
			ExpiresIn:    600,
			RefreshToken: "refresh-token",
			IDToken:      "id.jwt",
			Scope:        "openid profile",
		},
	}
	NewHandler(service, "").Register(router)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader("grant_type=authorization_code&code=raw-code&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&code_verifier=verifier"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client-one", "secret-one")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if service.lastTokenRequest.ClientID != "client-one" || service.lastTokenRequest.ClientAuthMethod != oidcdomain.TokenEndpointAuthMethodClientSecretBasic {
		t.Fatalf("expected basic auth credentials to be passed through, got %#v", service.lastTokenRequest)
	}

	var payload oidcdomain.TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if payload.AccessToken != "access.jwt" || payload.IDToken != "id.jwt" || payload.RefreshToken != "refresh-token" {
		t.Fatalf("unexpected token payload: %#v", payload)
	}
}

func TestUserInfoEndpointReturnsProfile(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(&stubOIDCService{
		userInfo: oidcdomain.UserInfo{
			Sub:               "user-1",
			PreferredUsername: "alice",
			Email:             "alice@example.com",
			Name:              "Alice",
			Groups:            []string{"platform"},
			Roles:             []string{"tenant_admin"},
			SID:               "session-1",
		},
	}, "").Register(router)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer access.jwt")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var payload oidcdomain.UserInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode userinfo response: %v", err)
	}

	if payload.Sub != "user-1" || payload.SID != "session-1" {
		t.Fatalf("unexpected userinfo payload: %#v", payload)
	}
}

func TestRevokeEndpointReturns200(t *testing.T) {
	router := chi.NewRouter()
	service := &stubOIDCService{}
	NewHandler(service, "").Register(router)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader("token=refresh-token&token_type_hint=refresh_token&client_id=client-one"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if service.lastRevokeRequest.Token != "refresh-token" || service.lastRevokeRequest.TokenTypeHint != oidcdomain.TokenTypeHintRefreshToken {
		t.Fatalf("unexpected revoke request: %#v", service.lastRevokeRequest)
	}
}

func TestLogoutEndpointClearsCookieAndRedirects(t *testing.T) {
	router := chi.NewRouter()
	NewHandler(&stubOIDCService{
		logoutResult: oidcdomain.LogoutResult{
			LoggedOut:   true,
			RedirectURI: "https://client.example.test/logout-callback",
		},
	}, defaultSessionCookieName).Register(router)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?client_id=client-one&post_logout_redirect_uri=https%3A%2F%2Fclient.example.test%2Flogout-callback", nil)
	req.AddCookie(&http.Cookie{Name: defaultSessionCookieName, Value: "session-cookie"})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "https://client.example.test/logout-callback" {
		t.Fatalf("unexpected logout redirect: %q", rec.Header().Get("Location"))
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != defaultSessionCookieName || cookies[0].MaxAge != -1 {
		t.Fatalf("expected cleared session cookie, got %#v", cookies)
	}
}

type stubOIDCService struct {
	discovery         oidcdomain.DiscoveryDocument
	jwks              oidcdomain.JWKSet
	authorizeResult   oidcdomain.AuthorizationResult
	authorizeErr      error
	tokenResponse     oidcdomain.TokenResponse
	tokenErr          error
	userInfo          oidcdomain.UserInfo
	userInfoErr       error
	revokeErr         error
	logoutResult      oidcdomain.LogoutResult
	logoutErr         error
	lastTokenRequest  oidcdomain.TokenRequest
	lastRevokeRequest oidcdomain.RevocationRequest
	lastLogoutRequest oidcdomain.LogoutRequest
}

func (s *stubOIDCService) DiscoveryDocument() oidcdomain.DiscoveryDocument {
	return s.discovery
}

func (s *stubOIDCService) JWKS() oidcdomain.JWKSet {
	return s.jwks
}

func (s *stubOIDCService) Authorize(ctx context.Context, input oidcdomain.AuthorizationRequest, rawSID string) (oidcdomain.AuthorizationResult, error) {
	return s.authorizeResult, s.authorizeErr
}

func (s *stubOIDCService) ExchangeCode(ctx context.Context, input oidcdomain.TokenRequest) (oidcdomain.TokenResponse, error) {
	s.lastTokenRequest = input
	return s.tokenResponse, s.tokenErr
}

func (s *stubOIDCService) UserInfo(ctx context.Context, rawAccessToken string) (oidcdomain.UserInfo, error) {
	return s.userInfo, s.userInfoErr
}

func (s *stubOIDCService) Revoke(ctx context.Context, input oidcdomain.RevocationRequest) error {
	s.lastRevokeRequest = input
	return s.revokeErr
}

func (s *stubOIDCService) Logout(ctx context.Context, rawSID string, input oidcdomain.LogoutRequest) (oidcdomain.LogoutResult, error) {
	s.lastLogoutRequest = input
	return s.logoutResult, s.logoutErr
}
