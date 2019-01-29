package services

import (
	"github.com/ca-gip/kubi/utils"
	"net/http"
	"net/http/httputil"
	"time"
)

// Unauthorized Header that could lead to security breach
var blacklistedHeaders = []string{"Authorization", "authorization", "Impersonate-User", "impersonate-user", "Impersonate-Group", "impersonate-group"}

// An authenticating proxy that forward all request to
// Kubernetes api server. Modification here can lead to security breach.
// The director erase dangerous headers < blacklisted header > to be protected
// from header spoofing.
func ProxyHandler(w http.ResponseWriter, r *http.Request) {

	director := func(req *http.Request) {

		req.URL.Host = utils.Config.ApiServerURL
		req.URL.Scheme = "https"
		token, err := CurrentJWT(w, req)

		// Header cleaning
		for headerIdx := range blacklistedHeaders {
			req.Header.Del(blacklistedHeaders[headerIdx])
		}
		req.Header.Set("Authorization", "Bearer "+utils.Config.KubeToken)
		req.Header.Set("Impersonate-User", "system:anonymous")
		req.Header.Set("Impersonate-Group", "system:unauthenticated")
		req.Header.Set("X-Content-Type-Options", "nosniff")

		// Header Manipulation
		if err == nil {
			for _, auth := range token.Auths {
				req.Header.Add("Impersonate-Group", auth.Namespace+"-"+auth.Role)
			}
			req.Header.Set("Impersonate-User", token.User)
		} else if err != nil {
			utils.Log.Error().Err(err)
		}
		utils.Log.Info().Msgf("Proxy user %s, %s %s, client %s", req.Header.Get("Impersonate-User"), r.Method, r.RequestURI, r.RemoteAddr)
	}

	proxy := &httputil.ReverseProxy{Director: director, Transport: &http.Transport{
		MaxIdleConns:    50,
		IdleConnTimeout: 60 * time.Second,
		TLSClientConfig: &utils.Config.ApiServerTLSConfig,
	}}
	proxy.ServeHTTP(w, r)
}
