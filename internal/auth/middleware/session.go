package middleware

import (
	"context"
	"net/http"

	authdomain "github.com/miloyuans/openauthing/internal/auth/domain"
	"github.com/miloyuans/openauthing/internal/auth/sessionctx"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
)

type SessionAuthenticator interface {
	Authenticate(ctx context.Context, sid string) (authdomain.Session, error)
}

func RequireSession(cookieName string, authenticator SessionAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err != nil || cookie.Value == "" {
				_ = httpjson.WriteAPIError(w, r, apierror.Unauthorized("authentication is required"))
				return
			}

			session, err := authenticator.Authenticate(r.Context(), cookie.Value)
			if err != nil {
				_ = httpjson.WriteErrorFrom(w, r, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(sessionctx.NewContext(r.Context(), session)))
		})
	}
}
