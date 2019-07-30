package utils

import (
	"fmt"
	"net/http"
	"time"
)

// Define our struct
type authenticationMiddleware struct {
	tokenUsers map[string]string
}

func Middleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		defer func() {
			httpDuration := time.Since(start)
			histogram.WithLabelValues(fmt.Sprintf("%s", r.RequestURI)).Observe(httpDuration.Seconds())
		}()
		next.ServeHTTP(w, r)
	})
}
