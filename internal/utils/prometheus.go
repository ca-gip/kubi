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

var ProjectCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_project_creation",
	Help: "Number of project created",
}, []string{"status", "name"})

var NamespaceCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_namespace_creation",
	Help: "Number of namespace created",
}, []string{"status", "name"})

var RoleBindingsCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_rolebindings_creation",
	Help: "Number of role bindings created",
}, []string{"status", "target_namespace", "name"})

var ServiceAccountCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_service_account_creation",
	Help: "Number of service account created",
}, []string{"status", "target_namespace", "name"})

var NetworkPolicyCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_network_policy_creation",
	Help: "Number of network policy created",
}, []string{"status", "target_namespace", "name"})
