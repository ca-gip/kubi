package main

import (
	"io"
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
	// TODO Remove this aberration - L17 should be a constructor and we should
	// use the config as live object instead of mutating it.
	utils.Config = config

	ldapClient := ldap.NewLDAPClient(config.Ldap)

	// TODO Move to config ( for validation )
	ecdsaPem, err := os.ReadFile(utils.ECDSAKeyPath)
	if err != nil {
		slog.Error("unable to read ECDSA private key", "error", err)
		os.Exit(1)
	}
	ecdsaPubPem, err := os.ReadFile(utils.ECDSAPublicPath)
	if err != nil {
		slog.Error("unable to read ECDSA public key", "error", err)
		os.Exit(1)
	}

	tokenIssuer, err := services.NewTokenIssuer(
		ecdsaPem,
		ecdsaPubPem,
		config.TokenLifeTime,
		config.ExtraTokenLifeTime,
		config.Locator,
		config.PublicApiServerURL,
		config.Tenant,
	)
	if err != nil {
		slog.Error("unable to create token issuer", "error", err)
		os.Exit(1)
	}

	router := mux.NewRouter()
	router.Use(middlewares.Prometheus)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		slog.Info("endpoint not routed", "method", req.Method, "url", req.URL.String())
	})

	router.HandleFunc("/ca", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, config.KubeCaText)
	}).Methods(http.MethodGet)

	router.HandleFunc("/config", middlewares.WithBasicAuth(ldapClient, tokenIssuer.GenerateConfig)).Methods(http.MethodGet)
	router.HandleFunc("/token", middlewares.WithBasicAuth(ldapClient, tokenIssuer.GenerateJWT)).Methods(http.MethodGet)
	router.Handle("/metrics", promhttp.Handler())

	slog.Info("starting server", "port", 8000)
	if err := http.ListenAndServeTLS(":8000", utils.TlsCertPath, utils.TlsKeyPath, router); err != nil {
		slog.Error("server failed to start", "error", err)
	}
}
