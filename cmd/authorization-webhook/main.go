package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/ca-gip/kubi/internal/middlewares"
	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

func main() {

	config, err := utils.MakeConfig()
	if err != nil {
		log.Fatal().Msg(fmt.Sprintf("Config error: %v", err))
	}
	utils.Config = config

	// TODO Move to config ( for validation )
	ecdsaPem, err := os.ReadFile(utils.ECDSAKeyPath)
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA private key: %v", err)
	}
	ecdsaPubPem, err := os.ReadFile(utils.ECDSAPublicPath)
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA public key: %v", err)
	}

	tokenIssuer, err := services.NewTokenIssuer(
		ecdsaPem,
		ecdsaPubPem,
		utils.Config.TokenLifeTime,
		utils.Config.ExtraTokenLifeTime, // This had to be included in refactor. TODO: Check side effects
		utils.Config.Locator,
		utils.Config.PublicApiServerURL,
		utils.Config.Tenant,
	)
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to create token issuer: %v", err)
	}

	router := mux.NewRouter()
	router.Use(middlewares.Prometheus)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})
	router.HandleFunc("/authenticate", services.AuthenticateHandler(tokenIssuer)).Methods(http.MethodPost)
	router.Handle("/metrics", promhttp.Handler())

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8001)
	utils.Log.Info().Msg(http.ListenAndServeTLS(":8001", utils.TlsCertPath, utils.TlsKeyPath, router).Error())

}
