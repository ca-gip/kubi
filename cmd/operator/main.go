package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/ca-gip/kubi/internal/ldap"
	"github.com/ca-gip/kubi/internal/middlewares"
	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	utils.InitLogger(os.Stdout)

	config, err := utils.MakeConfig()
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	ldapClient := ldap.NewLDAPClient(config.Ldap)

	go services.RefreshProjectsFromLdap(ldapClient, config.Whitelist)

	utils.Config = config

	// Generate namespace and role binding for ldap groups
	// no need to wait here
	slog.Info("generating resources from LDAP groups")

	router := mux.NewRouter()
	router.Use(middlewares.Prometheus)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		slog.Info("endpoint not routed", "method", req.Method, "url", req.URL.String())
	})
	router.Handle("/metrics", promhttp.Handler())

	services.WatchProjects()

	// TODO, get rid of the guard and auto watch netpol config if that's
	// relevant to keep.
	if config.NetworkPolicy {
		services.WatchNetPolConfig()
	} else {
		slog.Info("networkPolicies generation is disabled")
	}

	slog.Info("starting server", "port", 8002)
	if err := http.ListenAndServeTLS(":8002", utils.TlsCertPath, utils.TlsKeyPath, router); err != nil {
		slog.Error("server failed to start", "error", err)
	}

}
