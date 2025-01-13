package middlewares

import (
	"context"
	"fmt"
	"log/slog"
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
				slog.Info(fmt.Sprintf("user %v failed to authenticate, %v", username, err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// If the username and password are correct, then search for the user's group,
			// and only add the user and its group to the request context if successful.
			user, err = authenticator.AuthZ(user)
			if err != nil {
				// todo, log context r.url.
				slog.Warn(fmt.Sprintf("user %v failed authorization, logging for auditing purposes, reason:  %v", username, err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, *user) // Store the user value directly in the context.
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
