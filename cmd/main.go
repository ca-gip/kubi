package main

import (
	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
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

	// Generate namespace and role binding for ldap groups
	// no need to wait here

	utils.Log.Info().Msg("Generating resources from LDAP groups")
	services.GenerateAdminClusterRoleBinding()
	services.GenerateReaderClusterRoleBinding()

	err = services.GenerateResources()
	if err != nil {
		log.Error().Err(err)
	}

	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})

	router.HandleFunc("/ca", services.CA).Methods(http.MethodGet)
	router.HandleFunc("/refresh", services.RefreshK8SResources).Methods(http.MethodGet) // TODO, protect from users
	router.HandleFunc("/config", services.GenerateConfig).Methods(http.MethodGet)
	router.HandleFunc("/token", services.GenerateJWT).Methods(http.MethodGet)
	router.HandleFunc("/authenticate", services.AuthenticateHandler()).Methods(http.MethodPost)

	router.Handle("/metrics", promhttp.Handler())
	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8000)
	utils.Log.Fatal().Err(http.ListenAndServeTLS(":8000", utils.TlsCertPath, utils.TlsKeyPath, router))

}
