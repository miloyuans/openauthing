package handler

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	"github.com/miloyuans/openauthing/internal/auth/sessionctx"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/httpinput"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
)

const DefaultCookieName = "openauthing_session"

type SessionMiddleware func(http.Handler) http.Handler

type AuthService interface {
	Login(ctx context.Context, input authdomain.LoginInput, meta authdomain.RequestMeta) (authdomain.LoginResult, error)
	Me(ctx context.Context, session authdomain.Session) (authdomain.UserSummary, error)
	LogoutCurrent(ctx context.Context, session authdomain.Session) error
	ListSessions(ctx context.Context, session authdomain.Session) ([]authdomain.SessionListItem, error)
	RevokeSession(ctx context.Context, session authdomain.Session, id string) error
}

type Handler struct {
	service           AuthService
	cookieName        string
	secureCookies     bool
	sessionMiddleware SessionMiddleware
}

func NewHandler(service AuthService, cookieName string, secureCookies bool, sessionMiddleware SessionMiddleware) *Handler {
	if strings.TrimSpace(cookieName) == "" {
		cookieName = DefaultCookieName
	}

	return &Handler{
		service:           service,
		cookieName:        cookieName,
		secureCookies:     secureCookies,
		sessionMiddleware: sessionMiddleware,
	}
}

func (h *Handler) Register(r chi.Router) {
	r.Post("/auth/login", h.handleLogin)

	r.Group(func(r chi.Router) {
		if h.sessionMiddleware != nil {
			r.Use(h.sessionMiddleware)
		}
		r.Get("/auth/me", h.handleMe)
		r.Post("/auth/logout", h.handleLogout)
		r.Get("/sessions", h.handleListSessions)
		r.Post("/sessions/{id}/revoke", h.handleRevokeSession)
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var input authdomain.LoginInput
	if err := httpinput.DecodeJSON(r, &input); err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	result, err := h.service.Login(r.Context(), input, authdomain.RequestMeta{
		IP:        clientIP(r.RemoteAddr),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cookieName,
		Value:    result.SessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookies,
		Expires:  result.ExpiresAt,
		MaxAge:   int(timeUntil(result.ExpiresAt).Seconds()),
	})

	_ = httpjson.Write(w, r, http.StatusOK, result)
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionctx.FromContext(r.Context())
	if !ok {
		_ = httpjson.WriteAPIError(w, r, apierror.Unauthorized("authentication is required"))
		return
	}

	user, err := h.service.Me(r.Context(), session)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, user)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionctx.FromContext(r.Context())
	if !ok {
		_ = httpjson.WriteAPIError(w, r, apierror.Unauthorized("authentication is required"))
		return
	}

	if err := h.service.LogoutCurrent(r.Context(), session); err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.secureCookies,
		MaxAge:   -1,
	})

	_ = httpjson.Write(w, r, http.StatusOK, map[string]any{"logged_out": true})
}

func (h *Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionctx.FromContext(r.Context())
	if !ok {
		_ = httpjson.WriteAPIError(w, r, apierror.Unauthorized("authentication is required"))
		return
	}

	sessions, err := h.service.ListSessions(r.Context(), session)
	if err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, map[string]any{"items": sessions})
}

func (h *Handler) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionctx.FromContext(r.Context())
	if !ok {
		_ = httpjson.WriteAPIError(w, r, apierror.Unauthorized("authentication is required"))
		return
	}

	if err := h.service.RevokeSession(r.Context(), session, chi.URLParam(r, "id")); err != nil {
		_ = httpjson.WriteErrorFrom(w, r, err)
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, map[string]any{"revoked": true})
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}

	return remoteAddr
}

func timeUntil(expiresAt time.Time) time.Duration {
	until := time.Until(expiresAt)
	if until < 0 {
		return 0
	}

	return until
}
