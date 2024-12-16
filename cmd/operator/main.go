package main

import (
	"net/http"
	"os"
	"time"

	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
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

	// Generate namespace and role binding for ldap groups
	// no need to wait here
	utils.Log.Info().Msg("Generating resources from LDAP groups")

	err = services.GenerateResources()
	if err != nil {
		log.Error().Err(err)
	}
	router := mux.NewRouter()
	router.Use(utils.PrometheusMiddleware)
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		utils.Log.Warn().Msgf("%d %s %s", http.StatusNotFound, req.Method, req.URL.String())
	})
	router.Handle("/metrics", promhttp.Handler())

	if config.NetworkPolicy {
		services.WatchNetPolConfig()
	} else {
		utils.Log.Info().Msg("NetworkPolicies generation is disabled.")
	}
	services.WatchProjects()

	timerKubiRefresh := time.NewTicker(10 * time.Minute)
	go func() {
		for t := range timerKubiRefresh.C {

			utils.Log.Info().Msgf("Refreshing Projects at %s", t.String())
			services.RefreshK8SResources()
		}
	}()

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8002)
	utils.Log.Info().Msg(http.ListenAndServeTLS(":8002", utils.TlsCertPath, utils.TlsKeyPath, router).Error())

}
