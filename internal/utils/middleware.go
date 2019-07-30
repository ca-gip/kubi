package utils

import (
	"fmt"
	"net/http"
	"time"
)

func Middleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		defer func() {
			httpDuration := time.Since(start)
			Histogram.WithLabelValues(fmt.Sprintf("%s", r.RequestURI)).Observe(httpDuration.Seconds())
		}()
		next.ServeHTTP(w, r)
	})
}
