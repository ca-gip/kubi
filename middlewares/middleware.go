package middlewares

import (
	"intomy.land/kubi/utils"
	"net/http"
)

// A Simple middleware that log 404 error
// User to monitor unsuccess calls
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.Log.Info().Msgf("%s", r.RequestURI)
		next.ServeHTTP(w, r)
	})
}
