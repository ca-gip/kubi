package services

import (
	"crypto/ecdsa"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func Test_signJWTClaims(t *testing.T) {
	duration, _ := time.ParseDuration("4h")
	url, _ := url.Parse("https://kubi.example.com")

	ecdsaPem, err := os.ReadFile("./../../test/ecdsa-key.pem")
	if err != nil {
		t.Fatalf("Unable to read ECDSA private key: %v", err)
	}
	ecdsaPubPem, err := os.ReadFile("./../../test/ecdsa-pub.pem")
	if err != nil {
		t.Fatalf("Unable to read ECDSA public key: %v", err)
	}
	var ecdsaKey *ecdsa.PrivateKey
	var ecdsaPub *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(ecdsaPem); err != nil {
		t.Fatalf("Unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPub, err = jwt.ParseECPublicKeyFromPEM(ecdsaPubPem); err != nil {
		t.Fatalf("Unable to parse ECDSA public key: %v", err)
	}

	issuer := &TokenIssuer{
		EcdsaPrivate:       ecdsaKey,
		EcdsaPublic:        ecdsaPub,
		TokenDuration:      duration,
		ExtraTokenDuration: duration,
		Locator:            utils.KubiLocatorIntranet,
		PublicApiServerURL: url,
		Tenant:             "tenant",
	}

	claims := types.AuthJWTClaims{
		User:     "testuser",
		Contact:  "testuser@example.com",
		Locator:  issuer.Locator,
		Endpoint: issuer.PublicApiServerURL.Host,
		Tenant:   issuer.Tenant,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(duration).Unix(),
			Issuer:    "Kubi Server",
		},
	}

	t.Run("Valid JWT signing", func(t *testing.T) {
		token, err := issuer.signJWTClaims(claims)
		assert.Nil(t, err)
		assert.NotNil(t, token)

		parsedToken, err := jwt.ParseWithClaims(*token, &types.AuthJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return issuer.EcdsaPublic, nil
		})
		assert.Nil(t, err)
		assert.True(t, parsedToken.Valid)
	})

	t.Run("Invalid JWT signing with nil private key", func(t *testing.T) {
		issuer.EcdsaPrivate = nil
		token, err := issuer.signJWTClaims(claims)
		assert.NotNil(t, err)
		assert.Nil(t, token)
	})
}

func Test_generateUserJWTClaims(t *testing.T) {
	duration, _ := time.ParseDuration("4h")
	url, _ := url.Parse("https://kubi.example.com")
	stdAuths := []*types.Project{
		{
			Project:     "ns",
			Role:        "admin",
			Source:      "",
			Environment: "development",
			Contact:     "",
		},
		{
			Project:     "ns-devops-automation",
			Role:        "admin",
			Source:      "",
			Environment: "integration",
			Contact:     "",
		},
	}

	type args struct {
		auths                []*types.Project
		groups               []string
		username             string
		email                string
		hasAdminAccess       bool
		hasApplicationAccess bool
		hasOpsAccess         bool
		hasViewerAccess      bool
		hasServiceAccess     bool
		issuer               *TokenIssuer
	}
	type want struct {
		err    error
		auths  int // number of auths/projects
		groups []string
		user   string
	}
	var tests = []struct {
		name     string
		args     args
		expected want
	}{
		{
			name: "Regular user token contains project and all its groups",
			args: args{
				auths:                stdAuths,
				groups:               []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				username:             "foo",
				email:                "foo@bar.baz",
				hasAdminAccess:       false,
				hasApplicationAccess: false,
				hasOpsAccess:         false,
				hasViewerAccess:      false,
				hasServiceAccess:     false,
				issuer:               &TokenIssuer{EcdsaPrivate: &ecdsa.PrivateKey{}, EcdsaPublic: &ecdsa.PublicKey{}, TokenDuration: duration, Locator: utils.KubiLocatorIntranet, PublicApiServerURL: url},
			},
			expected: want{
				err:    nil,
				auths:  2,
				groups: []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				user:   "foo",
			},
		},
		{
			name: "Admin user does not have projects",
			args: args{
				auths:                stdAuths,
				groups:               []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				username:             "bar_admin",
				email:                "foo@bar.baz",
				hasAdminAccess:       true,
				hasApplicationAccess: false,
				hasOpsAccess:         false,
				hasViewerAccess:      false,
				hasServiceAccess:     false,
				issuer:               &TokenIssuer{EcdsaPrivate: &ecdsa.PrivateKey{}, EcdsaPublic: &ecdsa.PublicKey{}, TokenDuration: duration, Locator: utils.KubiLocatorIntranet, PublicApiServerURL: url},
			},
			expected: want{
				err:    nil,
				auths:  0,
				groups: []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				user:   "bar_admin",
			},
		},
		{
			name: "Appops user does not have projects",
			args: args{
				auths:                stdAuths,
				groups:               []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				username:             "baz_appops",
				email:                "foo@bar.baz",
				hasAdminAccess:       false,
				hasApplicationAccess: false,
				hasOpsAccess:         true,
				hasViewerAccess:      false,
				hasServiceAccess:     false,
				issuer:               &TokenIssuer{EcdsaPrivate: &ecdsa.PrivateKey{}, EcdsaPublic: &ecdsa.PublicKey{}, TokenDuration: duration, Locator: utils.KubiLocatorIntranet, PublicApiServerURL: url},
			},
			expected: want{
				err:    nil,
				auths:  0,
				groups: []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				user:   "baz_appops",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, gotErr := tt.args.issuer.generateUserJWTClaims(stdAuths, tt.args.groups, tt.args.username, tt.args.email, tt.args.hasAdminAccess, tt.args.hasApplicationAccess, tt.args.hasOpsAccess, tt.args.hasViewerAccess, tt.args.hasServiceAccess)
			if gotErr != nil {
				assert.Equal(t, gotErr, tt.expected.err)
			}
			assert.Equalf(t, gotToken.User, tt.expected.user, "generateUserJWTClaims(%v, %v, %v, %v, %v, %v, %v, %v)", tt.args.groups, tt.args.username, tt.args.email, tt.args.hasAdminAccess, tt.args.hasApplicationAccess, tt.args.hasOpsAccess, tt.args.hasViewerAccess, tt.args.hasServiceAccess)
			if !reflect.DeepEqual(gotToken.Groups, tt.expected.groups) {
				t.Errorf("generateUserJWTClaims() got = %v, want %v", gotToken.Groups, tt.expected.groups)
			}

			if len(gotToken.Auths) != tt.expected.auths {
				t.Errorf("generateUserJWTClaims() got %v as projects, wanted a total of %v projects", gotToken.Auths, tt.expected.auths)
			}
		})
	}
}
func Test_generateServiceJWTClaims(t *testing.T) {
	duration, _ := time.ParseDuration("4h")
	extraDuration, _ := time.ParseDuration("8h")
	url, _ := url.Parse("https://kubi.example.com")

	ecdsaPem, err := os.ReadFile("./../../test/ecdsa-key.pem")
	if err != nil {
		t.Fatalf("Unable to read ECDSA private key: %v", err)
	}
	ecdsaPubPem, err := os.ReadFile("./../../test/ecdsa-pub.pem")
	if err != nil {
		t.Fatalf("Unable to read ECDSA public key: %v", err)
	}
	var ecdsaKey *ecdsa.PrivateKey
	var ecdsaPub *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(ecdsaPem); err != nil {
		t.Fatalf("Unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPub, err = jwt.ParseECPublicKeyFromPEM(ecdsaPubPem); err != nil {
		t.Fatalf("Unable to parse ECDSA public key: %v", err)
	}

	issuer := &TokenIssuer{
		EcdsaPrivate:       ecdsaKey,
		EcdsaPublic:        ecdsaPub,
		TokenDuration:      duration,
		ExtraTokenDuration: extraDuration,
		Locator:            utils.KubiLocatorIntranet,
		PublicApiServerURL: url,
		Tenant:             "tenant",
	}

	t.Run("Valid service JWT claims generation", func(t *testing.T) {
		username := "testuser"
		email := "testuser@example.com"
		scopes := "promote"

		claims, err := issuer.generateServiceJWTClaims(username, email, scopes)
		assert.Nil(t, err)
		assert.Equal(t, username, claims.User)
		assert.Equal(t, email, claims.Contact)
		assert.Equal(t, issuer.Locator, claims.Locator)
		assert.Equal(t, issuer.PublicApiServerURL.Host, claims.Endpoint)
		assert.Equal(t, issuer.Tenant, claims.Tenant)
		assert.Equal(t, scopes, claims.Scopes)
		assert.WithinDuration(t, time.Now().Add(extraDuration), time.Unix(claims.ExpiresAt, 0), time.Minute)
		assert.Equal(t, "Kubi Server", claims.Issuer)
	})

	t.Run("Empty scopes in service JWT claims generation", func(t *testing.T) {
		username := "testuser"
		email := "testuser@example.com"
		scopes := ""

		claims, err := issuer.generateServiceJWTClaims(username, email, scopes)
		assert.Nil(t, err)
		assert.Equal(t, username, claims.User)
		assert.Equal(t, email, claims.Contact)
		assert.Equal(t, issuer.Locator, claims.Locator)
		assert.Equal(t, issuer.PublicApiServerURL.Host, claims.Endpoint)
		assert.Equal(t, issuer.Tenant, claims.Tenant)
		assert.Equal(t, scopes, claims.Scopes)
		assert.WithinDuration(t, time.Now().Add(extraDuration), time.Unix(claims.ExpiresAt, 0), time.Minute)
		assert.Equal(t, "Kubi Server", claims.Issuer)
	})
}
