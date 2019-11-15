package utils

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var TokenCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_valid_token_total",
	Help: "Total number of tokens issued",
}, []string{"status"})

var Histogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "kubi_http_requests",
	Help:    "Time per requests",
	Buckets: []float64{1, 2, 5, 6, 10}, //defining small buckets as this app should not take more than 1 sec to respond
}, []string{"path"}) // this will be partitioned by the HTTP code.

var ProjectCreationSuccess = promauto.NewCounter(prometheus.CounterOpts{
	Name: "kubi_project_creation_success",
	Help: "Number of project created with success",
})

var ProjectCreationError = promauto.NewCounter(prometheus.CounterOpts{
	Name: "kubi_project_creation_error",
	Help: "Number of project creation with an error",
})

var RoleBindingsCreationSuccess = promauto.NewCounter(prometheus.CounterOpts{
	Name: "kubi_rolebindings_creation_success",
	Help: "Number of role bindings created with success",
})

var RoleBindingsCreationError = promauto.NewCounter(prometheus.CounterOpts{
	Name: "kubi_rolebindings_creation_error",
	Help: "Number of role bindings creation with an error",
})

var NamespaceCreationSuccess = promauto.NewCounter(prometheus.CounterOpts{
	Name: "kubi_namespace_creation_success",
	Help: "Number of namespace created with success",
})

var NamespaceCreationError = promauto.NewCounter(prometheus.CounterOpts{
	Name: "kubi_namespace_creation_error",
	Help: "Number of namespace creation with an error",
})
