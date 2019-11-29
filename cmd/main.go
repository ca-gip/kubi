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
	"time"
)

func main() {

	config, err := utils.MakeConfig()
	if err != nil {
		log.Fatal().Msg("Config error")
		os.Exit(1)
	}
	utils.Config = config

	// Generate namespace and role binding for ldap groups
	// no need to wait here

	utils.Log.Info().Msg("Generating resources from LDAP groups")

	err = services.GenerateResources()
	if err != nil {
		log.Error().Err(err)
	}

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
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})

	router.HandleFunc("/ca", services.CA).Methods(http.MethodGet)
	router.HandleFunc("/config", tokenIssuer.GenerateConfig).Methods(http.MethodGet)
	router.HandleFunc("/token", tokenIssuer.GenerateJWT).Methods(http.MethodGet)
	router.HandleFunc("/authenticate", services.AuthenticateHandler(tokenIssuer)).Methods(http.MethodPost)
	router.Handle("/metrics", promhttp.Handler())

	if config.NetworkPolicy {
		services.WatchNetPolConfig()
	} else {
		utils.Log.Info().Msg("NetworkPolicies generation is disabled.")
	}
	services.WatchProjects()

	timerKubiRefresh := time.NewTicker(10 * time.Minute)
	go func() {
		for {
			select {
			case t := <-timerKubiRefresh.C:
				utils.Log.Info().Msgf("Refreshing Projects at ", t.String())
				services.RefreshK8SResources()
			}
		}
	}()

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8000)
	utils.Log.Info().Msg(http.ListenAndServeTLS(":8000", utils.TlsCertPath, utils.TlsKeyPath, router).Error())

}
