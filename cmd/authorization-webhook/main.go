package main

import (
	"crypto/ecdsa"
	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {

	config, err := utils.MakeConfig()
	if err != nil {
		log.Fatal().Msg("Config error")
		os.Exit(1)
	}
	utils.Config = config

	// TODO Move to config ( for validation )
	ecdsaPem, err := ioutil.ReadFile(utils.ECDSAKeyPath)
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA private key: %v", err)
	}
	ecdsaPubPem, err := ioutil.ReadFile(utils.ECDSAPublicPath)
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
	router.HandleFunc("/authenticate", services.AuthenticateHandler(tokenIssuer)).Methods(http.MethodPost)
	router.Handle("/metrics", promhttp.Handler())

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8001)
	utils.Log.Info().Msg(http.ListenAndServeTLS(":8001", utils.TlsCertPath, utils.TlsKeyPath, router).Error())

}
