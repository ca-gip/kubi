package main

import (
	"github.com/ca-gip/kubi/services"
	"github.com/ca-gip/kubi/utils"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"net/http"
)

func main() {

	config, err := utils.MakeConfig()
	if err != nil {
		log.Fatal().Msg("Config error")
	}
	utils.Config = config

	// Generate namespace and role binding for ldap groups
	// no need to wait here
	utils.Log.Info().Msg("Generating resources from Ldap backend")
	services.GenerateResourcesFromLdapGroups()

	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})
	//router.Use(middlewares.LoggingMiddleware)

	for _, prefix := range utils.ApiPrefix() {
		router.PathPrefix(prefix).Methods(http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete, http.MethodOptions).HandlerFunc(services.ProxyHandler)
	}

	router.HandleFunc("/ca", services.CA).Methods(http.MethodGet)
	router.HandleFunc("/refresh", services.RefreshK8SResources).Methods(http.MethodGet) // TODO, protect from users
	router.HandleFunc("/config", services.GenerateConfig).Methods(http.MethodGet)
	router.HandleFunc("/token", services.GenerateJWT).Methods(http.MethodGet)
	router.HandleFunc("/token/{username}", services.VerifyJWT).Methods(http.MethodPost)

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8000)
	utils.Log.Fatal().Err(http.ListenAndServeTLS(":8000", utils.TlsCertPath, utils.TlsKeyPath, router))

}
