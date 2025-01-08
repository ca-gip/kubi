package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/ca-gip/kubi/internal/ldap"
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
	// TODO Remove this aberration - L17 should be a constructor and we should
	// use the config as live object instead of mutating it.
	utils.Config = config

	ldapClient := ldap.NewLDAPClient(config.Ldap)

	// TODO Move to config ( for validation )
	ecdsaPem, err := os.ReadFile(utils.ECDSAKeyPath)
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA private key: %v", err)
	}
	ecdsaPubPem, err := os.ReadFile(utils.ECDSAPublicPath)
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA public key: %v", err)
	}

	tokenIssuer, err := services.NewTokenIssuer(ecdsaPem, ecdsaPubPem, utils.Config.TokenLifeTime, utils.Config.ExtraTokenLifeTime, utils.Config.Locator, utils.Config.PublicApiServerURL, utils.Config.Tenant)
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to create token issuer: %v", err)
	}

	router := mux.NewRouter()
	router.Use(middlewares.Prometheus)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})

	router.HandleFunc("/ca", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, config.KubeCaText)
	}).Methods(http.MethodGet)

	router.HandleFunc("/config", middlewares.WithBasicAuth(ldapClient, tokenIssuer.GenerateConfig)).Methods(http.MethodGet)
	router.HandleFunc("/token", middlewares.WithBasicAuth(ldapClient, tokenIssuer.GenerateJWT)).Methods(http.MethodGet)
	router.Handle("/metrics", promhttp.Handler())

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8000)
	utils.Log.Info().Msg(http.ListenAndServeTLS(":8000", utils.TlsCertPath, utils.TlsKeyPath, router).Error())

}
