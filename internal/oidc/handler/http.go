package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	oidcdomain "github.com/miloyuans/openauthing/internal/oidc/domain"
)

const defaultSessionCookieName = "openauthing_session"

type OIDCService interface {
	DiscoveryDocument() oidcdomain.DiscoveryDocument
	JWKS() oidcdomain.JWKSet
	Authorize(ctx context.Context, input oidcdomain.AuthorizationRequest, rawSID string) (oidcdomain.AuthorizationResult, error)
	ExchangeCode(ctx context.Context, input oidcdomain.TokenRequest) (oidcdomain.TokenResponse, error)
	UserInfo(ctx context.Context, rawAccessToken string) (oidcdomain.UserInfo, error)
	Revoke(ctx context.Context, input oidcdomain.RevocationRequest) error
	Logout(ctx context.Context, rawSID string, input oidcdomain.LogoutRequest) (oidcdomain.LogoutResult, error)
}

type Handler struct {
	service    OIDCService
	cookieName string
}

func NewHandler(service OIDCService, cookieName string) *Handler {
	if strings.TrimSpace(cookieName) == "" {
		cookieName = defaultSessionCookieName
	}

	return &Handler{
		service:    service,
		cookieName: cookieName,
	}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.handleDiscovery)
	r.Get("/.well-known/jwks.json", h.handleJWKS)
	r.Get("/oauth2/authorize", h.handleAuthorize)
	r.Post("/oauth2/token", h.handleToken)
	r.Get("/oauth2/userinfo", h.handleUserInfo)
	r.Post("/oauth2/revoke", h.handleRevoke)
	r.Get("/oauth2/logout", h.handleLogout)
	r.Post("/oauth2/logout", h.handleLogout)
}

func (h *Handler) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeProtocolJSON(w, http.StatusOK, h.service.DiscoveryDocument())
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeProtocolJSON(w, http.StatusOK, h.service.JWKS())
}

func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	result, err := h.service.Authorize(r.Context(), oidcdomain.AuthorizationRequest{
		ResponseType:        query.Get("response_type"),
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		Nonce:               query.Get("nonce"),
	}, h.readSessionCookie(r))
	if err != nil {
		h.writeProtocolError(w, r, err)
		return
	}

	http.Redirect(w, r, result.RedirectLocation(), http.StatusFound)
}

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request body must be valid form data")
		return
	}

	clientID, clientSecret, clientAuthMethod, err := parseClientCredentials(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	response, exchangeErr := h.service.ExchangeCode(r.Context(), oidcdomain.TokenRequest{
		GrantType:        r.FormValue("grant_type"),
		Code:             r.FormValue("code"),
		RefreshToken:     r.FormValue("refresh_token"),
		RedirectURI:      r.FormValue("redirect_uri"),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		ClientAuthMethod: clientAuthMethod,
		CodeVerifier:     r.FormValue("code_verifier"),
	})
	if exchangeErr != nil {
		h.writeProtocolError(w, r, exchangeErr)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeProtocolJSON(w, http.StatusOK, response)
}

func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	accessToken, err := parseBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	response, userInfoErr := h.service.UserInfo(r.Context(), accessToken)
	if userInfoErr != nil {
		h.writeProtocolError(w, r, userInfoErr)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeProtocolJSON(w, http.StatusOK, response)
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request body must be valid form data")
		return
	}

	clientID, clientSecret, clientAuthMethod, err := parseClientCredentials(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if revokeErr := h.service.Revoke(r.Context(), oidcdomain.RevocationRequest{
		Token:            r.FormValue("token"),
		TokenTypeHint:    r.FormValue("token_type_hint"),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		ClientAuthMethod: clientAuthMethod,
	}); revokeErr != nil {
		h.writeProtocolError(w, r, revokeErr)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	var clientID string
	var postLogoutRedirectURI string

	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query()
		clientID = query.Get("client_id")
		postLogoutRedirectURI = query.Get("post_logout_redirect_uri")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request body must be valid form data")
			return
		}
		clientID = r.FormValue("client_id")
		postLogoutRedirectURI = r.FormValue("post_logout_redirect_uri")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	result, err := h.service.Logout(r.Context(), h.readSessionCookie(r), oidcdomain.LogoutRequest{
		ClientID:              clientID,
		PostLogoutRedirectURI: postLogoutRedirectURI,
	})
	if err != nil {
		h.writeProtocolError(w, r, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	if result.RedirectURI != "" {
		http.Redirect(w, r, result.RedirectURI, http.StatusFound)
		return
	}

	writeProtocolJSON(w, http.StatusOK, map[string]any{"logged_out": result.LoggedOut})
}

func (h *Handler) writeProtocolError(w http.ResponseWriter, r *http.Request, err error) {
	var protocolErr oidcdomain.ProtocolError
	if errors.As(err, &protocolErr) {
		if protocolErr.ShouldRedirect() {
			http.Redirect(w, r, protocolErr.RedirectLocation(), protocolErr.Status)
			return
		}

		if protocolErr.Code == "invalid_client" {
			w.Header().Set("WWW-Authenticate", `Basic realm="openauthing-token"`)
		}
		if protocolErr.Code == "invalid_token" {
			writeBearerError(w, protocolErr.Status, protocolErr.Code, protocolErr.Description)
			return
		}
		writeOAuthError(w, protocolErr.Status, protocolErr.Code, protocolErr.Description)
		return
	}

	writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal server error")
}

func (h *Handler) readSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie(h.cookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}

func parseClientCredentials(r *http.Request) (string, string, string, error) {
	formClientID := strings.TrimSpace(r.FormValue("client_id"))
	formClientSecret := strings.TrimSpace(r.FormValue("client_secret"))

	if basicClientID, basicClientSecret, ok := r.BasicAuth(); ok {
		if formClientSecret != "" {
			return "", "", "", errors.New("client_secret must not be sent in both basic auth and form body")
		}
		if formClientID != "" && formClientID != basicClientID {
			return "", "", "", errors.New("client_id in basic auth and form body must match")
		}

		return strings.TrimSpace(basicClientID), strings.TrimSpace(basicClientSecret), oidcdomain.TokenEndpointAuthMethodClientSecretBasic, nil
	}

	if formClientSecret != "" {
		return formClientID, formClientSecret, oidcdomain.TokenEndpointAuthMethodClientSecretPost, nil
	}

	return formClientID, formClientSecret, oidcdomain.TokenEndpointAuthMethodNone, nil
}

func writeProtocolJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	payload := map[string]string{"error": code}
	if description != "" {
		payload["error_description"] = description
	}

	writeProtocolJSON(w, status, payload)
}

func writeBearerError(w http.ResponseWriter, status int, code, description string) {
	header := `Bearer realm="openauthing-userinfo"`
	if code != "" {
		header += `, error="` + code + `"`
	}
	if description != "" {
		header += `, error_description="` + description + `"`
	}
	w.Header().Set("WWW-Authenticate", header)
	writeOAuthError(w, status, code, description)
}

func parseBearerToken(header string) (string, error) {
	value := strings.TrimSpace(header)
	if value == "" {
		return "", errors.New("bearer token is required")
	}

	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("authorization header must use bearer token")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("bearer token is required")
	}

	return token, nil
}
