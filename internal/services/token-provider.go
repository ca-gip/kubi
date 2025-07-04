package services

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ca-gip/kubi/internal/middlewares"
	"github.com/ca-gip/kubi/internal/project"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

var (
	TokenCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kubi_valid_token_total",
		Help: "Total number of tokens issued",
	}, []string{"status"})

	KubiTokenSizeHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "kubi_token_size",
		Help:    "size of a kubi ldap token in bytes",
		Buckets: []float64{512, 1024, 4096, 16384, 65536},
	})
)

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
		slog.Debug("user will have transversal access, removing all the projects", "user", username, "admin", hasAdminAccess, "application", hasApplicationAccess, "ops", hasOpsAccess, "service", hasServiceAccess)
		// To be removed when ppl will have the right to have both transversal and project access
		// Currently removed because too many groups.
		auths = []*types.Project{}
	} else {
		slog.Debug("user will have access to the projects", "user", username, "projects", fmt.Sprint(auths))
	}

	var expirationTime time.Time

	if hasServiceAccess {
		slog.Debug("The user will have an extra token duration", "user", username, "duration", issuer.ExtraTokenDuration)
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

	var claims types.AuthJWTClaims
	var err error
	var token *string = nil

	if len(scopes) > 0 {
		if !(user.IsAdmin || user.IsAppOps || user.IsCloudOps) {
			return nil, fmt.Errorf("the user %s cannot generate extra token with no transversal access (admin: %v, application: %v, ops: %v)", user.Username, user.IsAdmin, user.IsAppOps, user.IsCloudOps)
		}
		claims, err = issuer.generateServiceJWTClaims(user.Username, user.Email, scopes)
		if err != nil {
			return nil, fmt.Errorf("unable to generate the token %v", err)
		}
	} else {
		// Do not pass the full group list, as they wont parse as Projects.
		// When the Project Access will be removed, the createAccessToken will become a simple wrapper around generateUserJWTClaims and their signature.
		// We can then use Factory or Strategy pattern to clean up the code further.
		projects := project.GetProjectsFromGrouplist(user.ProjectAccesses)

		claims, err = issuer.generateUserJWTClaims(projects, user.Groups, user.Username, user.Email, user.IsAdmin, user.IsAppOps, user.IsCloudOps, user.IsViewer, user.IsService)
		if err != nil {
			return nil, fmt.Errorf("unable to generate the token %v", err)
		}
	}

	token, err = issuer.signJWTClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("unable to sign the token %v", err)
	}

	if token == nil {
		return nil, fmt.Errorf("the token is nil")
	}
	TokenCounter.WithLabelValues("token_success").Inc()
	return token, nil
}

func (issuer *TokenIssuer) GenerateJWT(w http.ResponseWriter, r *http.Request) {

	userContext := r.Context().Value(middlewares.UserContextKey)
	if userContext == nil {
		slog.Error("No user found in the context")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := userContext.(types.User)
	scopes := r.URL.Query().Get("scopes")

	token, err := issuer.createAccessToken(user, scopes)

	if err != nil {
		TokenCounter.WithLabelValues("token_error").Inc()
		slog.Error("granting token fail for user", "user", user.Username, "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	slog.Debug("token generated", "user", user.Username, "scopes", scopes)
	KubiTokenSizeHistogram.Observe(float64(len(*token)))
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
		slog.Error("No user found in the context")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := userContext.(types.User)

	token, err := issuer.createAccessToken(user, "")
	// no need to generate config if the user cannot access it.
	if err != nil {
		TokenCounter.WithLabelValues("token_error").Inc()
		slog.Error("failed to grant token", "user", user.Username, "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	slog.Debug("granting token for user", "user", user.Username)

	// Create a DNS 1123 cluster name and user name
	yml, err := generateKubeConfig(issuer.PublicApiServerURL.String(), utils.Config.KubeCa, user, token)
	if err != nil {
		slog.Error("failed to generate config for user", "user", user.Username, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/x-yaml; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	w.Write(yml)
}

func generateKubeConfig(serverURL string, CA string, user types.User, token *string) ([]byte, error) {
	clusterName := strings.TrimPrefix(serverURL, "https://api.")
	username := fmt.Sprintf("%s_%s", user.Username, clusterName)

	config := &types.KubeConfig{
		ApiVersion: "v1",
		Kind:       "Config",
		Clusters: []types.KubeConfigCluster{
			{
				Name: clusterName,
				Cluster: types.KubeConfigClusterData{
					Server:          serverURL,
					CertificateData: CA,
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
		if issuer.EcdsaPublic == nil {
			return nil, fmt.Errorf("the public key is nil")
		}
		return issuer.EcdsaPublic, nil
	})
	if err != nil {
		slog.Info("Bad token", "error", err.Error())
		return nil, err
	}

	if claims, ok := token.Claims.(*types.AuthJWTClaims); ok && token.Valid {
		return claims, nil
	} else {
		slog.Info("Auth token is invalid")
		return nil, err
	}
}
