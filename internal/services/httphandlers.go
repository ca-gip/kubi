package services

import (
	"context"
	"net/http"

	"github.com/ca-gip/kubi/internal/ldap"
)

type contextKey string

const userContextKey contextKey = "user"

func WithBasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the username and password from the request
		// Authorization header. If no Authentication header is present
		// or the header value is invalid, then the 'ok' return value
		// will be false.
		username, password, ok := r.BasicAuth()
		if ok {
			if len(password) == 0 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			user, err := ldap.AuthenticateUser(username, password)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, user) // This is ugly, but at least it cleans up the code and matches the usual patterns.
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// If the Authentication header is not present, is invalid, or the
		// username or password is wrong, then set a WWW-Authenticate
		// header to inform the client that we expect them to use basic
		// authentication and send a 401 Unauthorized response.
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
