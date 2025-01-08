package middlewares

import (
	"context"
	"net/http"

	"github.com/ca-gip/kubi/pkg/types"
)

type contextKey string

const UserContextKey contextKey = "user"

type Authenticator interface {
	AuthN(username, password string) (*types.User, error)
	AuthZ(user *types.User) (*types.User, error)
}

func WithBasicAuth(authenticator Authenticator, next http.HandlerFunc) http.HandlerFunc {
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

			user, err := authenticator.AuthN(username, password)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// If the username and password are correct, then search for the user's group,
			// and only add the user and its group to the request context if successful.
			user, err = authenticator.AuthZ(user)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user) // This is ugly, but at least it cleans up the code and matches the usual patterns.
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
