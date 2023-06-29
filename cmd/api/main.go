package main

import (
	"crypto/ecdsa"
	"net/http"
	"os"

	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

func main() {

	config, err := utils.MakeConfig()
	if err != nil {
		log.Fatal().Msg("Config error")
		os.Exit(1)
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
	var ecdsaKey *ecdsa.PrivateKey
	var ecdsaPub *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(ecdsaPem); err != nil {
		utils.Log.Fatal().Msgf("Unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPub, err = jwt.ParseECPublicKeyFromPEM(ecdsaPubPem); err != nil {
		utils.Log.Fatal().Msgf("Unable to parse ECDSA public key: %v", err)
	}

	tokenIssuer := &services.TokenIssuer{
		EcdsaPrivate:       ecdsaKey,
		EcdsaPublic:        ecdsaPub,
		TokenDuration:      utils.Config.TokenLifeTime,
		ExtraTokenDuration: utils.Config.ExtraTokenLifeTime,
		Locator:            utils.Config.Locator,
		PublicApiServerURL: utils.Config.PublicApiServerURL,
		Tenant:             utils.Config.Tenant,
	}

	router := mux.NewRouter()
	router.Use(utils.PrometheusMiddleware)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})

	router.HandleFunc("/ca", services.CA).Methods(http.MethodGet)
	router.HandleFunc("/config", tokenIssuer.GenerateConfig).Methods(http.MethodGet)
	router.HandleFunc("/token", tokenIssuer.GenerateJWT).Methods(http.MethodGet)
	router.Handle("/metrics", promhttp.Handler())

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8000)
	utils.Log.Info().Msg(http.ListenAndServeTLS(":8000", utils.TlsCertPath, utils.TlsKeyPath, router).Error())

}
