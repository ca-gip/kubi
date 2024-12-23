package services

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ca-gip/kubi/internal/ldap"
	"github.com/ca-gip/kubi/internal/middlewares"
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
// TODO evrardjp: Pass User as parameters.
func (issuer *TokenIssuer) generateUserJWTClaims(auths []*types.Project, groups []string, username string, email string, hasAdminAccess bool, hasApplicationAccess bool, hasOpsAccess bool, hasViewerAccess bool, hasServiceAccess bool) (types.AuthJWTClaims, error) {

	if hasAdminAccess || hasApplicationAccess || hasOpsAccess || hasServiceAccess {
		utils.Log.Debug().Msgf("The user %s will have transversal access, removing all the projects (admin: %v, application: %v, ops: %v, service: %v)", username, hasAdminAccess, hasApplicationAccess, hasOpsAccess, hasServiceAccess)
		// To be removed when ppl will have the right to have both transversal and project access
		// Currently removed because too many groups.
		auths = []*types.Project{}
	} else {
		utils.Log.Debug().Msgf("The user %s will have access to the projects %v", username, auths)
	}

	var expirationTime time.Time

	if hasServiceAccess {
		utils.Log.Debug().Msgf("The user %s will have an extra token duration of %v", username, issuer.ExtraTokenDuration)
		expirationTime = time.Now().Add(issuer.ExtraTokenDuration)
	} else {
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

func (issuer *TokenIssuer) signJWTClaims(claims types.AuthJWTClaims) (*string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	if issuer.EcdsaPrivate == nil {
		return nil, fmt.Errorf("the private key is nil") // should not happen, avoid panic.
	}
	signedToken, err := token.SignedString(issuer.EcdsaPrivate)
	if err != nil {
		return nil, err
	}
	return &signedToken, err
}

func (issuer *TokenIssuer) createAccessToken(user types.User, scopes string) (*string, error) {

	memberships := &ldap.UserMemberships{}
	if err := memberships.FromUserDN(user.UserDN); err != nil {
		utils.TokenCounter.WithLabelValues("token_error").Inc()
		return nil, err
	}
	groups := memberships.ListGroups()
	utils.Log.Info().Msgf("The user %s is part of the groups %v", user.Username, groups)

	// to keep for historical reasons: We continue to issue tokens with old data until
	// ArgoCD + promote + other? is updated to use the new groups.
	isAdmin := len(memberships.AdminAccess) > 0
	isAppOps := (len(memberships.AppOpsAccess) > 0) || (len(memberships.CustomerOpsAccess) > 0)
	isViewer := len(memberships.ViewerAccess) > 0
	isService := len(memberships.ServiceAccess) > 0
	isCloudOps := len(memberships.CloudOpsAccess) > 0

	var claims types.AuthJWTClaims
	var err error
	var token *string = nil

	if len(scopes) > 0 {
		if !(isAdmin || isAppOps || isCloudOps) {
			utils.TokenCounter.WithLabelValues("token_error").Inc()
			return nil, fmt.Errorf("the user %s cannot generate extra token with no transversal access (admin: %v, application: %v, ops: %v)", user.Username, isAdmin, isAppOps, isCloudOps)
		}
		claims, err = issuer.generateServiceJWTClaims(user.Username, user.Email, scopes)
		if err != nil {
			utils.TokenCounter.WithLabelValues("token_error").Inc()
			return nil, fmt.Errorf("unable to generate the token %v", err)
		}
	} else {
		// Do not pass the full group list, as they wont parse as Projects.
		projectAccesses := GetAllProjects(memberships.ListClusterGroups())

		claims, err = issuer.generateUserJWTClaims(projectAccesses, groups, user.Username, user.Email, isAdmin, isAppOps, isCloudOps, isViewer, isService)
		if err != nil {
			utils.TokenCounter.WithLabelValues("token_error").Inc()
			return nil, fmt.Errorf("unable to generate the token %v", err)
		}
	}

	token, err = issuer.signJWTClaims(claims)
	if err != nil {
		utils.TokenCounter.WithLabelValues("token_error").Inc()
		return nil, fmt.Errorf("unable to sign the token %v", err)
	}

	if token == nil {
		utils.TokenCounter.WithLabelValues("token_error").Inc()
		return nil, fmt.Errorf("the token is nil")
	}
	// TODO: Expose a metric or a log about the type of token generated (its scope)
	utils.TokenCounter.WithLabelValues("token_success").Inc()
	return token, nil
}

func (issuer *TokenIssuer) GenerateJWT(w http.ResponseWriter, r *http.Request) {

	userContext := r.Context().Value(middlewares.UserContextKey)
	if userContext == nil {
		utils.Log.Error().Msgf("No user found in the context")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := userContext.(types.User)
	scopes := r.URL.Query().Get("scopes")

	token, err := issuer.createAccessToken(user, scopes)

	if err != nil {
		utils.Log.Error().Msgf("Granting token fail for user %v", user.Username)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	utils.Log.Info().Msgf("Granting token for user %v with scopes %v", user.Username, scopes)
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, *token)
}

// GenerateConfig generates a config in yaml, including JWT token
// and cluster information. It can be directly used out of the box
// by kubectl. It returns a well formatted yaml
// TODO: Refactor to use the same code as GenerateJWT
func (issuer *TokenIssuer) GenerateConfig(w http.ResponseWriter, r *http.Request) {

	userContext := r.Context().Value(middlewares.UserContextKey)
	if userContext == nil {
		utils.Log.Error().Msgf("No user found in the context")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := userContext.(types.User)

	token, err := issuer.createAccessToken(user, "")
	// no need to generate config if the user cannot access it.
	if err != nil {
		utils.Log.Error().Msgf("Granting token fail for user %v", user.Username)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	utils.Log.Info().Msgf("Granting token for user %v", user.Username)

	// Create a DNS 1123 cluster name and user name
	yml, err := generateKubeConfig(user, token)
	if err != nil {
		utils.Log.Error().Err(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/x-yaml; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	w.Write(yml)
}

func generateKubeConfig(user types.User, token *string) ([]byte, error) {
	clusterName := strings.TrimPrefix(utils.Config.PublicApiServerURL, "https://api.")
	username := fmt.Sprintf("%s_%s", user.Username, clusterName)

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
	return yml, err
}

func (issuer *TokenIssuer) VerifyToken(usertoken string) (*types.AuthJWTClaims, error) {

	// this verifies the token and its signature
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
