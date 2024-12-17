package utils

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

func PrometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		path, err := route.GetPathTemplate()
		if err != nil {
			log.Printf("Error getting path template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		timer := prometheus.NewTimer(Histogram.WithLabelValues(path))
		next.ServeHTTP(w, r)
		timer.ObserveDuration()
	})
}
