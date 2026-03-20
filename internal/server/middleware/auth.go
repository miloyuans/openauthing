package middleware

import "net/http"

// AuthPlaceholder keeps the protected route boundary in place until real auth is implemented.
func AuthPlaceholder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
