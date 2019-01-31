package services

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ca-gip/kubi/authenticator"
	"github.com/ca-gip/kubi/types"
	"github.com/ca-gip/kubi/utils"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"k8s.io/api/authentication/v1beta1"
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

func GenerateKubeT(w http.ResponseWriter, r *http.Request) {
	bodyString, err := ioutil.ReadAll(r.Body)
	if err != nil {
		utils.Log.Error().Err(err)
	}
	utils.Log.Info().Msg(string(bodyString))
	tokenReview := v1beta1.TokenReview{}
	err = json.Unmarshal(bodyString, &tokenReview)
	utils.Log.Info().Msg("token is" + tokenReview.Spec.Token)
	if err != nil {
		utils.Log.Error().Msg(err.Error())
	}

	token, err := CurrentJWT(tokenReview.Spec.Token)

	if err != nil {
		resp := v1beta1.TokenReview{
			Status: v1beta1.TokenReviewStatus{
				Authenticated: false,
			},
		}
		w.WriteHeader(401)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	} else {
		groups := []string{}
		// Other ldap group are injected
		for _, auth := range token.Auths {
			groups = append(groups, fmt.Sprintf("%s-%s", auth.Namespace, auth.Role))
		}
		if token.AdminAccess {
			groups = append(groups, utils.KubiClusterRoleBindingName)
		}

		resp := v1beta1.TokenReview{
			Status: v1beta1.TokenReviewStatus{
				Authenticated: true,
				User: v1beta1.UserInfo{
					Username: token.User,
					Groups:   groups,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			utils.Log.Error().Msg(err.Error())
		}

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
					Server:          "https://" + r.Host,
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

func VerifyJWT(w http.ResponseWriter, r *http.Request) {
	bodyString, err := ioutil.ReadAll(r.Body)
	token, err := jwt.ParseWithClaims(string(bodyString), &types.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})

	if claims, ok := token.Claims.(*types.AuthJWTClaims); ok && token.Valid {
		utils.Log.Info().Msgf("%v %v", claims.Auths, claims.StandardClaims.ExpiresAt)
	} else {
		utils.Log.Info().Msgf("%b", err)
	}

	w.WriteHeader(http.StatusOK)
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
