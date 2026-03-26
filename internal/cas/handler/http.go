package handler

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	casdomain "github.com/miloyuans/openauthing/internal/cas/domain"
)

var (
	loginPageTemplate = template.Must(template.New("cas-login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>openauthing CAS Login</title>
  <style>
    :root { color-scheme: light; }
    body { margin: 0; font-family: "Segoe UI", sans-serif; background: linear-gradient(180deg, #f8fafc 0%, #e2e8f0 100%); color: #0f172a; }
    .shell { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
    .card { width: 100%; max-width: 420px; background: white; border-radius: 18px; box-shadow: 0 18px 50px rgba(15, 23, 42, 0.12); padding: 28px; }
    h1 { margin: 0 0 8px; font-size: 28px; }
    p { margin: 0 0 20px; color: #475569; line-height: 1.5; }
    label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 600; }
    input { width: 100%; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 12px; padding: 12px 14px; font-size: 15px; margin-bottom: 16px; }
    button { width: 100%; border: 0; border-radius: 12px; padding: 12px 14px; background: #0f172a; color: white; font-size: 15px; font-weight: 600; cursor: pointer; }
    button[disabled] { opacity: 0.7; cursor: wait; }
    .hint { font-size: 13px; color: #64748b; margin-top: 14px; }
    .error { display: none; margin-bottom: 16px; padding: 10px 12px; border-radius: 10px; background: #fef2f2; color: #991b1b; font-size: 14px; }
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <h1>Sign In</h1>
      <p>Use your openauthing account to continue the CAS login flow.</p>
      <div id="error" class="error"></div>
      <form id="login-form">
        <label for="identifier">Username or email</label>
        <input id="identifier" name="identifier" autocomplete="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button id="submit" type="submit">Continue</button>
      </form>
      <div class="hint">After sign-in, openauthing will continue the pending CAS service login automatically.</div>
    </div>
  </div>
  <script>
    const returnTo = {{ printf "%q" .ReturnTo }};
    const form = document.getElementById("login-form");
    const button = document.getElementById("submit");
    const errorBox = document.getElementById("error");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorBox.style.display = "none";
      errorBox.textContent = "";
      button.disabled = true;
      const identifier = document.getElementById("identifier").value.trim();
      const password = document.getElementById("password").value;
      const payload = identifier.includes("@")
        ? { email: identifier, password }
        : { username: identifier, password };
      try {
        const response = await fetch("/api/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(payload)
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          const message = body && body.error && body.error.message
            ? body.error.message
            : "Login failed. Please check your credentials.";
          throw new Error(message);
        }
        window.location.assign(returnTo);
      } catch (error) {
        errorBox.textContent = error && error.message ? error.message : "Login failed.";
        errorBox.style.display = "block";
      } finally {
        button.disabled = false;
      }
    });
  </script>
</body>
</html>`))
	infoPageTemplate = template.Must(template.New("cas-info").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>openauthing CAS Login</title>
</head>
<body>
  <p>{{ .Message }}</p>
</body>
</html>`))
)

type Service interface {
	NormalizeService(rawService string) (string, error)
	Login(ctx context.Context, session authdomain.Session, rawService string) (string, error)
	ValidateServiceTicket(ctx context.Context, rawService, rawTicket string, withAttributes bool) (casdomain.ValidationResult, error)
	ServiceResponseXML(result casdomain.ValidationResult, withAttributes bool) ([]byte, error)
	FailureResponseXML(code, message string) ([]byte, error)
}

type SessionAuthenticator interface {
	Authenticate(ctx context.Context, sid string) (authdomain.Session, error)
}

type Handler struct {
	service       Service
	cookieName    string
	authenticator SessionAuthenticator
}

type loginPageData struct {
	ReturnTo string
}

func NewHandler(service Service, cookieName string, authenticator SessionAuthenticator) *Handler {
	if strings.TrimSpace(cookieName) == "" {
		cookieName = "openauthing_session"
	}

	return &Handler{
		service:       service,
		cookieName:    cookieName,
		authenticator: authenticator,
	}
}

func (h *Handler) Register(r chi.Router) {
	r.Get("/cas/login", h.handleLogin)
	r.Get("/cas/serviceValidate", h.handleServiceValidate)
	r.Get("/cas/p3/serviceValidate", h.handleP3ServiceValidate)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	rawService := strings.TrimSpace(r.URL.Query().Get("service"))
	normalizedService := rawService
	if rawService != "" {
		value, err := h.service.NormalizeService(rawService)
		if err != nil {
			writeHTTPProtocolError(w, err)
			return
		}
		normalizedService = value
	}

	session, authenticated := h.currentSession(r.Context(), r)
	if !authenticated {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = loginPageTemplate.Execute(w, loginPageData{ReturnTo: r.URL.RequestURI()})
		return
	}

	if rawService == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = infoPageTemplate.Execute(w, map[string]string{
			"Message": "You already have an active openauthing session. Add service to issue a CAS service ticket.",
		})
		return
	}

	rawTicket, err := h.service.Login(r.Context(), session, normalizedService)
	if err != nil {
		writeHTTPProtocolError(w, err)
		return
	}

	redirectURI, err := appendTicket(normalizedService, rawTicket)
	if err != nil {
		http.Error(w, "failed to construct service redirect", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (h *Handler) handleServiceValidate(w http.ResponseWriter, r *http.Request) {
	h.handleValidation(w, r, false)
}

func (h *Handler) handleP3ServiceValidate(w http.ResponseWriter, r *http.Request) {
	h.handleValidation(w, r, true)
}

func (h *Handler) handleValidation(w http.ResponseWriter, r *http.Request, withAttributes bool) {
	result, err := h.service.ValidateServiceTicket(
		r.Context(),
		r.URL.Query().Get("service"),
		r.URL.Query().Get("ticket"),
		withAttributes,
	)
	if err != nil {
		writeXMLProtocolError(w, h.service, err)
		return
	}

	body, err := h.service.ServiceResponseXML(result, withAttributes)
	if err != nil {
		http.Error(w, "failed to render cas response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *Handler) currentSession(ctx context.Context, r *http.Request) (authdomain.Session, bool) {
	if h.authenticator == nil {
		return authdomain.Session{}, false
	}

	cookie, err := r.Cookie(h.cookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return authdomain.Session{}, false
	}

	session, err := h.authenticator.Authenticate(ctx, cookie.Value)
	if err != nil {
		return authdomain.Session{}, false
	}

	return session, true
}

func appendTicket(rawService, rawTicket string) (string, error) {
	parsed, err := neturl.Parse(rawService)
	if err != nil {
		return "", err
	}

	query := parsed.Query()
	query.Set("ticket", rawTicket)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func writeHTTPProtocolError(w http.ResponseWriter, err error) {
	var protocolErr casdomain.ProtocolError
	if errors.As(err, &protocolErr) {
		http.Error(w, protocolErr.Message, protocolErr.Status)
		return
	}

	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func writeXMLProtocolError(w http.ResponseWriter, service Service, err error) {
	var protocolErr casdomain.ProtocolError
	if !errors.As(err, &protocolErr) {
		protocolErr = casdomain.ProtocolError{
			Status:  http.StatusInternalServerError,
			Code:    casdomain.FailureCodeInternalError,
			Message: "internal server error",
		}
	}

	body, renderErr := service.FailureResponseXML(protocolErr.Code, protocolErr.Message)
	if renderErr != nil {
		http.Error(w, "failed to render cas failure response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	status := http.StatusOK
	if protocolErr.Status >= http.StatusInternalServerError {
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
