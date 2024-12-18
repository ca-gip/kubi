package services

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	ldap "github.com/ca-gip/kubi/internal/authprovider"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v2"
)

type TokenIssuer struct {
	EcdsaPrivate       *ecdsa.PrivateKey
	EcdsaPublic        *ecdsa.PublicKey
	TokenDuration      time.Duration
	ExtraTokenDuration time.Duration
	Locator            string
	PublicApiServerURL *url.URL
	Tenant             string
}

func NewTokenIssuer(privateKey []byte, publicKey []byte, tokenDuration string, extraTokenDuration string, locator string, publicApiServerURL string, tenant string) (*TokenIssuer, error) {
	duration, err := time.ParseDuration(tokenDuration)
	if err != nil {
		return nil, fmt.Errorf("unable to parse duration %s", tokenDuration)
	}

	extraDuration, err := time.ParseDuration(extraTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("unable to parse extra Token duration %s", extraTokenDuration)
	}
	apiURL, err := url.Parse(publicApiServerURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url %s", publicApiServerURL)
	}

	var ecdsaKey *ecdsa.PrivateKey
	var ecdsaPub *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(privateKey); err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPub, err = jwt.ParseECPublicKeyFromPEM(publicKey); err != nil {
		return nil, fmt.Errorf("unable to parse ECDSA public key: %v", err)
	}

	return &TokenIssuer{
		EcdsaPrivate:       ecdsaKey,
		EcdsaPublic:        ecdsaPub,
		TokenDuration:      duration,
		ExtraTokenDuration: extraDuration,
		Locator:            locator,
		PublicApiServerURL: apiURL,
		Tenant:             tenant,
	}, nil
}

// Generate an service token from a user account
// The semantic of this token is held by the target backend, ex: service api, promotion api...
// Only users with "transverse" access can generate extra tokens
func (issuer *TokenIssuer) generateServiceJWTClaims(username string, email string, scopes string) (types.AuthJWTClaims, error) {

	expiration := time.Now().Add(issuer.ExtraTokenDuration)
	utils.Log.Info().Msgf("Generating extra token with scope %s ", scopes)

	// Create the Claims
	claims := types.AuthJWTClaims{
		Auths:    []*types.Project{},
		User:     username,
		Contact:  email,
		Locator:  issuer.Locator,
		Endpoint: issuer.PublicApiServerURL.Host,
		Tenant:   issuer.Tenant,
		Scopes:   scopes,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
			Issuer:    "Kubi Server",
		},
	}

	return claims, nil
}

// Generate a user token from a user account
func (issuer *TokenIssuer) generateUserJWTClaims(groups []string, username string, email string, hasAdminAccess bool, hasApplicationAccess bool, hasOpsAccess bool, hasViewerAccess bool, hasServiceAccess bool) (types.AuthJWTClaims, error) {

	var auths = []*types.Project{}
	if hasAdminAccess || hasApplicationAccess || hasOpsAccess || hasServiceAccess {
		utils.Log.Info().Msgf("The user %s will have transversal access, removing all the projects (admin: %v, application: %v, ops: %v, service: %v)", username, hasAdminAccess, hasApplicationAccess, hasOpsAccess, hasServiceAccess)
	} else {
		auths = GetUserNamespaces(groups)
		utils.Log.Info().Msgf("The user %s will have access to the projects %v", username, auths)
	}

	var expirationTime time.Time

	switch hasServiceAccess {
	case true:
		expirationTime = time.Now().Add(issuer.ExtraTokenDuration)
	default:
		expirationTime = time.Now().Add(issuer.TokenDuration)
	}

	// Create the Claims
	claims := types.AuthJWTClaims{
		Auths:             auths,
		User:              username,
		Groups:            groups,
		Contact:           email,
		AdminAccess:       hasAdminAccess,
		ApplicationAccess: hasApplicationAccess,
		OpsAccess:         hasOpsAccess,
		ServiceAccess:     hasServiceAccess,
		ViewerAccess:      hasViewerAccess,
		Locator:           issuer.Locator,
		Endpoint:          issuer.PublicApiServerURL.Host,
		Tenant:            issuer.Tenant,

		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "Kubi Server",
		},
	}

	return claims, nil
}

func signJWTClaims(claims types.AuthJWTClaims, issuer *TokenIssuer) (*string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	signedToken, err := token.SignedString(issuer.EcdsaPrivate)
	if err != nil {
		return nil, err
	}
	return &signedToken, err
}

func (issuer *TokenIssuer) baseGenerateToken(auth types.Auth, scopes string) (*string, error) {

	userDN, mail, err := ldap.AuthenticateUser(auth.Username, auth.Password)
	if err != nil {
		return nil, err
	}

	groups, err := ldap.GetUserGroups(*userDN)
	utils.Log.Info().Msgf("The user %s is part of the groups %v", auth.Username, groups)
	if err != nil {
		utils.TokenCounter.WithLabelValues("token_error").Inc()
		return nil, err
	}

	isAdmin := ldap.HasAdminAccess(*userDN)
	isApplication := ldap.HasApplicationAccess(*userDN)
	isOps := ldap.HasOpsAccess(*userDN)
	isViewer := ldap.HasViewerAccess(*userDN)
	isService := ldap.HasServiceAccess(*userDN)

	var token *string = nil
	if len(scopes) > 0 {
		if !(isAdmin || isApplication || isOps) {
			return nil, fmt.Errorf("the user %s cannot generate extra token with no transversal access (admin: %v, application: %v, ops: %v)", auth.Username, isAdmin, isApplication, isOps)
		}
		claims, err := issuer.generateServiceJWTClaims(auth.Username, *mail, scopes)
		if err != nil {
			utils.TokenCounter.WithLabelValues("token_error").Inc()
			return nil, fmt.Errorf("unable to generate the token %v", err)
		}
		token, err = signJWTClaims(claims, issuer)
		if err != nil {
			utils.TokenCounter.WithLabelValues("token_error").Inc()
			return nil, fmt.Errorf("unable to sign the token %v", err)
		}
	} else {
		claims, err := issuer.generateUserJWTClaims(groups, auth.Username, *mail, isAdmin, isApplication, isOps, isViewer, isService)
		if err != nil {
			utils.TokenCounter.WithLabelValues("token_error").Inc()
			return nil, fmt.Errorf("unable to generate the token %v", err)
		}
		token, err = signJWTClaims(claims, issuer)
		if err != nil {
			utils.TokenCounter.WithLabelValues("token_error").Inc()
			return nil, fmt.Errorf("unable to sign the token %v", err)
		}
	}

	if token != nil {
		utils.TokenCounter.WithLabelValues("token_success").Inc()
	}

	return token, nil
}

func (issuer *TokenIssuer) GenerateJWT(w http.ResponseWriter, r *http.Request) {
	auth, err := issuer.basicAuth(r)
	if err != nil {
		utils.Log.Info().Err(err)
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "Basic Auth: Invalid credentials")
	}

	scopes := r.URL.Query().Get("scopes")
	token, err := issuer.baseGenerateToken(*auth, scopes)

	if err != nil {
		utils.Log.Error().Msgf("Granting token fail for user %v", auth.Username)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if token == nil {
		utils.Log.Error().Msgf("Granting token fail for user %v", auth.Username)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	utils.Log.Info().Msgf("Granting token for user %v", auth.Username)
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, *token)
}

// GenerateConfig generates a config in yaml, including JWT token
// and cluster information. It can be directly used out of the box
// by kubectl. It returns a well formatted yaml
func (issuer *TokenIssuer) GenerateConfig(w http.ResponseWriter, r *http.Request) {
	auth, err := issuer.basicAuth(r)

	if err != nil {
		utils.Log.Info().Msg(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "Basic Auth: Invalid credentials")
		return
	}

	token, err := issuer.baseGenerateToken(*auth, utils.Empty)
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

	// Create a DNS 1123 cluster name and user name
	clusterName := strings.TrimPrefix(utils.Config.PublicApiServerURL, "https://api.")
	username := fmt.Sprintf("%s_%s", auth.Username, clusterName)

	config := &types.KubeConfig{
		ApiVersion: "v1",
		Kind:       "Config",
		Clusters: []types.KubeConfigCluster{
			{
				Name: clusterName,
				Cluster: types.KubeConfigClusterData{
					Server:          utils.Config.PublicApiServerURL,
					CertificateData: utils.Config.KubeCa,
				},
			},
		},
		CurrentContext: username,
		Contexts: []types.KubeConfigContext{
			{
				Name: username,
				Context: types.KubeConfigContextData{
					Cluster: clusterName,
					User:    username,
				},
			},
		},
		Users: []types.KubeConfigUser{
			{
				User: types.KubeConfigUserToken{Token: *token},
				Name: username},
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

	tokenSplits := strings.Split(usertoken, ".")
	if len(tokenSplits) != 3 {
		return nil, fmt.Errorf("the token %s is not a JWT token", usertoken)
	}

	if err != nil {
		utils.Log.Info().Msgf("Bad token: %v. The public token part is %s", err.Error(), tokenSplits[1])
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
	if len(tokenSplits) != 3 {
		return fmt.Errorf("the token %s is not a JWT token", usertoken)
	}
	return method.Verify(strings.Join(tokenSplits[0:2], "."), tokenSplits[2], issuer.EcdsaPublic)
}

func (issuer *TokenIssuer) basicAuth(r *http.Request) (*types.Auth, error) {
	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if len(auth) != 2 || auth[0] != "Basic" {
		return nil, fmt.Errorf("invalid auth")
	}
	payload, err := base64.StdEncoding.DecodeString(auth[1])
	if err != nil {
		return nil, fmt.Errorf("not valid base64 string %v - %w", auth[1], err)
	}
	pair := strings.SplitN(string(payload), ":", 2)
	return &types.Auth{Username: pair[0], Password: pair[1]}, nil
}
