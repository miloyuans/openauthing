package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
	"github.com/miloyuans/openauthing/internal/shared/requestid"
)

func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("request panic recovered",
						"request_id", requestid.FromContext(r.Context()),
						"panic", recovered,
						"stack", string(debug.Stack()),
					)
					_ = httpjson.WriteAPIError(w, r, apierror.Internal())
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
