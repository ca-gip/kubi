package main

import (
	"github.com/gorilla/mux"
	"intomy.land/kube-ldap/services"
	"intomy.land/kube-ldap/utils"
	"log"
	"net/http"
)

func main() {

	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})
	//router.Use(middlewares.LoggingMiddleware)

	for _, prefix := range utils.ApiPrefix {
		router.PathPrefix(prefix).Methods(http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete, http.MethodOptions).HandlerFunc(services.ProxyHandler)
	}

	router.HandleFunc("/ca", services.CA).Methods(http.MethodGet)
	router.HandleFunc("/config", services.GenerateConfig).Methods(http.MethodGet)
	router.HandleFunc("/token", services.GenerateJWT).Methods(http.MethodGet)
	router.HandleFunc("/token/{username}", services.VerifyJWT).Methods(http.MethodPost)

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8000)
	log.Fatal(http.ListenAndServeTLS(":8000", "/var/run/secrets/certs/tls.crt", "/var/run/secrets/certs/tls.key", router))

}
