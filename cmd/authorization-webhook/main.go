package main

import (
	"log/slog"
	"net/http"
	"os"

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
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}
	utils.Config = config

	// TODO Move to config ( for validation )
	ecdsaPem, err := os.ReadFile(utils.ECDSAKeyPath)
	if err != nil {
		slog.Error("failed to read ECDSA private key", "error", err)
		os.Exit(1)
	}
	ecdsaPubPem, err := os.ReadFile(utils.ECDSAPublicPath)
	if err != nil {
		slog.Error("failed to read ECDSA public key", "error", err)
		os.Exit(1)
	}

	tokenIssuer, err := services.NewTokenIssuer(
		ecdsaPem,
		ecdsaPubPem,
		config.TokenLifeTime,
		config.ExtraTokenLifeTime, // This had to be included in refactor. TODO: Check side effects
		config.Locator,
		config.PublicApiServerURL,
		config.Tenant,
	)
	if err != nil {
		slog.Error("failed to create token issuer", "error", err)
		os.Exit(1)
	}

	router := mux.NewRouter()
	router.Use(middlewares.Prometheus)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		slog.Info("endpoint not routed", "method", req.Method, "url", req.URL.String())
	})
	router.HandleFunc("/authenticate", services.AuthenticateHandler(tokenIssuer)).Methods(http.MethodPost)
	router.Handle("/metrics", promhttp.Handler())

	slog.Info("starting server", "port", 8001)
	if err := http.ListenAndServeTLS(":8001", utils.TlsCertPath, utils.TlsKeyPath, router); err != nil {
		slog.Error("server failed to start", "error", err)
		os.Exit(1)
	}

}
