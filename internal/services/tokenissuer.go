package services

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/ca-gip/kubi/internal/authprovider"
	"github.com/ca-gip/kubi/internal/types"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenIssuer struct {
	EcdsaPrivate       *ecdsa.PrivateKey
	EcdsaPublic        *ecdsa.PublicKey
	TokenDuration      string
	Locator            string
	PublicApiServerURL string
	Tenant             string
}

func (issuer *TokenIssuer) GenerateUserToken(groups []string, username string, email string, hasAdminAccess bool, hasApplicationAccess bool, hasOpsAccess bool) (*string, error) {

	var auths = GetUserNamespaces(groups)

	duration, err := time.ParseDuration(issuer.TokenDuration)
	current := time.Now().Add(duration)
	url, _ := url.Parse(issuer.PublicApiServerURL)

	// Create the Claims
	claims := types.AuthJWTClaims{
		Auths:             auths,
		User:              username,
		Contact:           email,
		AdminAccess:       hasAdminAccess,
		ApplicationAccess: hasApplicationAccess,
		OpsAccess:         hasOpsAccess,
		Locator:           issuer.Locator,
		Endpoint:          url.Host,
		Tenant:            issuer.Tenant,

		StandardClaims: jwt.StandardClaims{
			ExpiresAt: current.Unix(),
			Issuer:    "Kubi Server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	signedToken, err := token.SignedString(issuer.EcdsaPrivate)
	if err != nil {
		return nil, err
	}
	return &signedToken, err
}

func (issuer *TokenIssuer) baseGenerateToken(auth types.Auth) (*string, error) {

	userDN, mail, err := ldap.AuthenticateUser(auth.Username, auth.Password)
	if err != nil {
		return nil, err
	}

	groups, err := ldap.GetUserGroups(*userDN)
	if err != nil {
		utils.TokenCounter.WithLabelValues("token_error").Inc()
		return nil, err
	}
	token, err := issuer.GenerateUserToken(groups, auth.Username, *mail, ldap.HasAdminAccess(*userDN), ldap.HasApplicationAccess(*userDN), ldap.HasOpsAccess(*userDN))

	if err != nil {
		utils.TokenCounter.WithLabelValues("token_error").Inc()
		return nil, err
	}
	utils.TokenCounter.WithLabelValues("token_success").Inc()
	return token, nil
}

func (issuer *TokenIssuer) GenerateJWT(w http.ResponseWriter, r *http.Request) {
	err, auth := issuer.basicAuth(r)
	if err != nil {
		utils.Log.Info().Err(err)
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "Basic Auth: Invalid credentials")
	}

	token, err := issuer.baseGenerateToken(*auth)
	if err == nil {
		utils.Log.Info().Msgf("Granting token for user %v", auth.Username)
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, *token)
	} else {
		utils.Log.Error().Msgf("Granting token fail for user %v", auth.Username)
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// GenerateConfig generates a config in yaml, including JWT token
// and cluster information. It can be directly used out of the box
// by kubectl. It returns a well formatted yaml
func (issuer *TokenIssuer) GenerateConfig(w http.ResponseWriter, r *http.Request) {
	err, auth := issuer.basicAuth(r)

	if err != nil {
		utils.Log.Info().Err(err)
		utils.Log.Info().Msg(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "Basic Auth: Invalid credentials")

	}

	token, err := issuer.baseGenerateToken(*auth)
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

func (issuer *TokenIssuer) CurrentJWT(usertoken string) (*types.AuthJWTClaims, error) {

	token, err := jwt.ParseWithClaims(usertoken, &types.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return issuer.EcdsaPublic, nil
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

func (issuer *TokenIssuer) VerifyToken(usertoken string) error {
	method := jwt.SigningMethodES512
	tokenSplits := strings.Split(usertoken, ".")
	if len(tokenSplits) < 3 {
		errors.New(fmt.Sprintf("The token %s id not a JWT token", usertoken))
	}
	return method.Verify(strings.Join(tokenSplits[0:2], "."), tokenSplits[2], issuer.EcdsaPublic)
}

func (issuer *TokenIssuer) basicAuth(r *http.Request) (error, *types.Auth) {
	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if len(auth) != 2 || auth[0] != "Basic" {
		var err = errors.New("Invalid Auth")
		return err, nil
	}
	payload, _ := base64.StdEncoding.DecodeString(auth[1])
	pair := strings.SplitN(string(payload), ":", 2)
	return nil, &types.Auth{Username: pair[0], Password: pair[1]}
}
