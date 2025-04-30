package middlewares

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var Histogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "kubi_http_requests",
	Help:    "Time per requests",
	Buckets: []float64{1, 2, 5, 6, 10}, //defining small buckets as this app should not take more than 1 sec to respond
}, []string{"path"}) // this will be partitioned by the HTTP .

func Prometheus(next http.Handler) http.Handler {
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
