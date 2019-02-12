package services

import (
	"encoding/base64"
	"errors"
	"github.com/ca-gip/kubi/internal/authprovider"
	"github.com/ca-gip/kubi/internal/types"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var Config *types.Config

var signingKey, _ = ioutil.ReadFile(utils.TlsKeyPath)

func generateUserToken(groups []string, username string, hasAdminAccess bool) (string, error) {
	var auths = GetUserNamespaces(groups)

	duration, err := time.ParseDuration(utils.Config.TokenLifeTime)
	time := time.Now().Add(duration)

	// Create the Claims
	claims := types.AuthJWTClaims{
		auths,
		username,
		hasAdminAccess,
		jwt.StandardClaims{
			ExpiresAt: time.Unix(),
			Issuer:    "Kubi Server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString(signingKey)

	return signedToken, err
}

func baseGenerateToken(auth types.Auth) (*string, error) {

	userDN, err := ldap.AuthenticateUser(auth.Username, auth.Password)
	if err != nil {
		return nil, err
	}

	groups, err := ldap.GetUserGroups(*userDN)
	if err != nil {
		return nil, err
	}
	token, err := generateUserToken(groups, auth.Username, ldap.HasAdminAccess(*userDN))

	if err != nil {
		return nil, err
	}
	return &token, nil
}

func GenerateJWT(w http.ResponseWriter, r *http.Request) {
	err, auth := basicAuth(r)
	if err != nil {
		utils.Log.Info().Err(err)
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "Basic Auth: Invalid credentials")
	}

	token, err := baseGenerateToken(*auth)

	if token != nil {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, *token)
	}

}

// GenerateConfig generate a config in yaml, including JWT token
// and cluster information. It can be directly used out of the box
// by kubectl. It return a well formatted yaml
func GenerateConfig(w http.ResponseWriter, r *http.Request) {
	err, auth := basicAuth(r)

	if err != nil {
		utils.Log.Info().Err(err)
		utils.Log.Info().Msg(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "Basic Auth: Invalid credentials")

	}

	token, err := baseGenerateToken(*auth)
	if err == nil {
		utils.Log.Info().Msgf("Granting token for user %v", auth.Username)
	} else {
		utils.Log.Error().Msgf("Granting token fail for user %v", auth.Username)
	}

	if err != nil {
		utils.Log.Info().Err(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	config := &types.KubeConfig{
		ApiVersion: "v1",
		Kind:       "Config",
		Clusters: []types.KubeConfigCluster{
			{
				Name: "kubernetes",
				Cluster: types.KubeConfigClusterData{
					Server:          utils.Config.PublicApiServerURL,
					CertificateData: utils.Config.KubeCa,
				},
			},
		},
		CurrentContext: "kubernetes" + "-" + auth.Username,
		Contexts: []types.KubeConfigContext{
			{
				Name: "kubernetes" + "-" + auth.Username,
				Context: types.KubeConfigContextData{
					Cluster: "kubernetes",
					User:    auth.Username,
				},
			},
		},
		Users: []types.KubeConfigUser{
			{
				User: types.KubeConfigUserToken{Token: *token},
				Name: auth.Username},
		},
	}

	yml, err := yaml.Marshal(config)

	utils.Log.Error().Err(err)
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "text/x-yaml; charset=utf-8")
	w.Write(yml)

}

func CurrentJWT(usertoken string) (*types.AuthJWTClaims, error) {

	token, err := jwt.ParseWithClaims(usertoken, &types.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		utils.Log.Info().Msgf("Bad token: %v", err.Error())
		return nil, err
	}
	if claims, ok := token.Claims.(*types.AuthJWTClaims); ok && token.Valid {
		return claims, nil
	} else {
		utils.Log.Info().Msgf("Auth token is invalid")
		return nil, err
	}
}

func basicAuth(r *http.Request) (error, *types.Auth) {
	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if len(auth) != 2 || auth[0] != "Basic" {
		var err = errors.New("Invalid Auth")
		return err, nil
	}
	payload, _ := base64.StdEncoding.DecodeString(auth[1])
	pair := strings.SplitN(string(payload), ":", 2)
	return nil, &types.Auth{Username: pair[0], Password: pair[1]}
}
