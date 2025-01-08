package main

import (
	"fmt"
	"net/http"
	"time"

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

	ldapClient := ldap.NewLDAPClient(config.Ldap)

	utils.Config = config

	// Generate namespace and role binding for ldap groups
	// no need to wait here
	utils.Log.Info().Msg("Generating resources from LDAP groups")

	router := mux.NewRouter()
	router.Use(middlewares.Prometheus)
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

			utils.Log.Info().Msgf("Create or Update Projects at %s", t.String())
			projects, err := ldapClient.ListProjects()
			if err != nil {
				utils.Log.Error().Msgf("cannot get project list from ldap: %v", err)
			}
			services.HandleProject(projects)
		}
	}()

	utils.Log.Info().Msgf(" Preparing to serve request, port: %d", 8002)
	utils.Log.Info().Msg(http.ListenAndServeTLS(":8002", utils.TlsCertPath, utils.TlsKeyPath, router).Error())

}
