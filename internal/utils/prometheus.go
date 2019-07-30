package utils

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var TokenCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_valid_token_total",
	Help: "Total number of tokens issued",
}, []string{"status"})

var histogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "kubi_http_requests",
	Help:    "Time per requests",
	Buckets: []float64{1, 2, 5, 6, 10}, //defining small buckets as this app should not take more than 1 sec to respond
}, []string{"code", "path"}) // this will be partitioned by the HTTP code.
