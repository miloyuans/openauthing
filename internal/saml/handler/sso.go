package handler

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
)

var (
	loginPageTemplate = template.Must(template.New("saml-login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>openauthing SAML Login</title>
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
      <p>Use your openauthing account to continue the SAML login flow.</p>
      <div id="error" class="error"></div>
      <form id="login-form">
        <label for="identifier">Username or email</label>
        <input id="identifier" name="identifier" autocomplete="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button id="submit" type="submit">Continue</button>
      </form>
      <div class="hint">After sign-in, openauthing will continue the pending SAML request automatically.</div>
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
	autoPostTemplate = template.Must(template.New("saml-post").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Redirecting to service provider</title>
</head>
<body onload="document.forms[0].submit()">
  <form method="post" action="{{ .ACSURL }}">
    <input type="hidden" name="SAMLResponse" value="{{ .SAMLResponse }}">
    {{ if .RelayState }}<input type="hidden" name="RelayState" value="{{ .RelayState }}">{{ end }}
    <noscript>
      <p>JavaScript is disabled. Click continue to finish SAML login.</p>
      <button type="submit">Continue</button>
    </noscript>
  </form>
</body>
</html>`))
	infoPageTemplate = template.Must(template.New("saml-info").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>openauthing SAML Login</title>
</head>
<body>
  <p>{{ .Message }}</p>
</body>
</html>`))
)

type loginPageData struct {
	ReturnTo string
}

func (h *Handler) handleSSO(w http.ResponseWriter, r *http.Request) {
	input, err := readSPInitiatedRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, ok := h.currentSession(r.Context(), r)
	if !ok {
		http.Redirect(w, r, "/saml/idp/login?continue="+url.QueryEscape(ssoContinueTarget(r, input)), http.StatusFound)
		return
	}

	result, err := h.service.CompleteSPInitiated(r.Context(), session, input)
	if err != nil {
		writeSAMLError(w, err)
		return
	}

	writeAutoPostPage(w, result)
}

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	continueTarget, ok := sanitizeContinue(query.Get("continue"))
	if !ok {
		http.Error(w, "continue must be a safe local path", http.StatusBadRequest)
		return
	}

	if session, authenticated := h.currentSession(r.Context(), r); authenticated {
		switch {
		case continueTarget != "":
			http.Redirect(w, r, continueTarget, http.StatusFound)
			return
		case strings.TrimSpace(query.Get("app_id")) != "" || strings.TrimSpace(query.Get("sp_entity_id")) != "":
			result, err := h.service.CompleteIDPInitiated(r.Context(), session, query.Get("app_id"), query.Get("sp_entity_id"))
			if err != nil {
				writeSAMLError(w, err)
				return
			}
			writeAutoPostPage(w, result)
			return
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = infoPageTemplate.Execute(w, map[string]string{
				"Message": "You already have an active openauthing session. Add app_id or sp_entity_id to start IdP-initiated SSO.",
			})
			return
		}
	}

	returnTo := continueTarget
	if returnTo == "" {
		returnTo = r.URL.RequestURI()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = loginPageTemplate.Execute(w, loginPageData{ReturnTo: returnTo})
}

func readSPInitiatedRequest(r *http.Request) (samldomain.SPInitiatedRequest, error) {
	if err := r.ParseForm(); err != nil {
		return samldomain.SPInitiatedRequest{}, errors.New("request must be valid form data")
	}

	binding := strings.TrimSpace(r.FormValue("binding"))
	if binding == "" {
		if r.Method == http.MethodPost {
			binding = samldomain.BindingHTTPPost
		} else {
			binding = samldomain.BindingHTTPRedirect
		}
	}

	return samldomain.SPInitiatedRequest{
		Binding:     binding,
		SAMLRequest: r.FormValue("SAMLRequest"),
		RelayState:  r.FormValue("RelayState"),
		SigAlg:      r.FormValue("SigAlg"),
		Signature:   r.FormValue("Signature"),
	}, nil
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

func sanitizeContinue(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", true
	}
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		return value, true
	}
	return "", false
}

func ssoContinueTarget(r *http.Request, input samldomain.SPInitiatedRequest) string {
	if r.Method == http.MethodGet && input.Binding != samldomain.BindingHTTPPost {
		return r.URL.RequestURI()
	}

	query := url.Values{}
	query.Set("binding", input.Binding)
	query.Set("SAMLRequest", input.SAMLRequest)
	if strings.TrimSpace(input.RelayState) != "" {
		query.Set("RelayState", input.RelayState)
	}
	if strings.TrimSpace(input.SigAlg) != "" {
		query.Set("SigAlg", input.SigAlg)
	}
	if strings.TrimSpace(input.Signature) != "" {
		query.Set("Signature", input.Signature)
	}
	return "/saml/idp/sso?" + query.Encode()
}

func writeSAMLError(w http.ResponseWriter, err error) {
	var protocolErr samldomain.ProtocolError
	if errors.As(err, &protocolErr) {
		http.Error(w, protocolErr.Message, protocolErr.Status)
		return
	}

	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func writeAutoPostPage(w http.ResponseWriter, result samldomain.LoginResult) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = autoPostTemplate.Execute(w, result)
}
