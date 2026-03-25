package handler

import (
	"net/http"
	"strings"

	samldomain "github.com/miloyuans/openauthing/internal/saml/domain"
)

func (h *Handler) handleSLO(w http.ResponseWriter, r *http.Request) {
	input, err := readLogoutRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := h.service.HandleLogoutRequest(r.Context(), input)
	if err != nil {
		writeSAMLError(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	writeLogoutPostPage(w, result)
}

func readLogoutRequest(r *http.Request) (samldomain.LogoutRequest, error) {
	if err := r.ParseForm(); err != nil {
		return samldomain.LogoutRequest{}, err
	}

	binding := strings.TrimSpace(r.FormValue("binding"))
	if binding == "" {
		if r.Method == http.MethodPost {
			binding = samldomain.BindingHTTPPost
		} else {
			binding = samldomain.BindingHTTPRedirect
		}
	}

	return samldomain.LogoutRequest{
		Binding:     binding,
		SAMLRequest: r.FormValue("SAMLRequest"),
		RelayState:  r.FormValue("RelayState"),
		SigAlg:      r.FormValue("SigAlg"),
		Signature:   r.FormValue("Signature"),
	}, nil
}

func writeLogoutPostPage(w http.ResponseWriter, result samldomain.LogoutResult) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = autoPostTemplate.Execute(w, map[string]string{
		"ACSURL":       result.SLOURL,
		"SAMLResponse": result.SAMLResponse,
		"RelayState":   result.RelayState,
	})
}
