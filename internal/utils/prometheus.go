package utils

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var TokenCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_valid_token_total",
	Help: "Total number of tokens issued",
}, []string{"status"})

var ProjectCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_project_creation",
	Help: "Number of project created",
}, []string{"status", "name"})

var NamespaceCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_namespace_creation",
	Help: "Number of namespace created",
}, []string{"status", "name"})

var ServiceAccountCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_service_account_creation",
	Help: "Number of service account created",
}, []string{"status", "target_namespace", "name"})

var NetworkPolicyCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_network_policy_creation",
	Help: "Number of network policy created",
}, []string{"status", "target_namespace", "name"})
