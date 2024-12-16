package services

import (
	"crypto/ecdsa"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestECDSA(t *testing.T) {
	ecdsaPem, err := os.ReadFile("./../../test/ecdsa-key.pem")
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA private key: %v", err)
	}
	ecdsaPubPem, err := os.ReadFile("./../../test/ecdsa-pub.pem")
	if err != nil {
		utils.Log.Fatal().Msgf("Unable to read ECDSA public key: %v", err)
	}
	var ecdsaKey *ecdsa.PrivateKey
	var ecdsaPub *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(ecdsaPem); err != nil {
		utils.Log.Fatal().Msgf("Unable to parse ECDSA private key: %v", err)
	}
	if ecdsaPub, err = jwt.ParseECPublicKeyFromPEM(ecdsaPubPem); err != nil {
		utils.Log.Fatal().Msgf("Unable to parse ECDSA public key: %v", err)
	}

	issuer := TokenIssuer{
		EcdsaPrivate:  ecdsaKey,
		EcdsaPublic:   ecdsaPub,
		TokenDuration: "4h",
		Locator:       utils.KubiLocatorIntranet,
	}

	t.Run("Generate a valid User token", func(t *testing.T) {

		token, err := issuer.GenerateUserToken([]string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin"}, "unit", "noreply@demo.com", true, true, false, false, false)
		assert.Nil(t, err)
		assert.NotNil(t, token)
		utils.Log.Info().Msgf("The token is %s", *token)

		method := jwt.SigningMethodES512

		tokenSplits := strings.Split(*token, ".")

		err = method.Verify(strings.Join(tokenSplits[0:2], "."), tokenSplits[2], ecdsaPub)
		assert.Nil(t, err)
	})
}

func Test_generateUserClaims(t *testing.T) {
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
		auths  []string
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
				auths: []*types.Project{
					&types.Project{
						Project:     "ns-development",
						Role:        "",
						Source:      "",
						Environment: "",
						Contact:     "",
					},
					&types.Project{
						Project:     "ns-devops-automation-integration",
						Role:        "",
						Source:      "",
						Environment: "",
						Contact:     "",
					},
				},
				groups:               []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				username:             "foo",
				email:                "foo@bar.baz",
				hasAdminAccess:       false,
				hasApplicationAccess: false,
				hasOpsAccess:         false,
				hasViewerAccess:      false,
				hasServiceAccess:     false,
				issuer:               &TokenIssuer{EcdsaPrivate: &ecdsa.PrivateKey{}, EcdsaPublic: &ecdsa.PublicKey{}, TokenDuration: "4h", Locator: utils.KubiLocatorIntranet},
			},
			expected: want{
				err:    nil,
				auths:  []string{"ns-development", "ns-devops-automation-integration"},
				groups: []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				user:   "foo",
			},
		},
		{
			name: "Admin user does not have projects",
			args: args{
				auths: []*types.Project{
					&types.Project{
						Project:     "ns-development",
						Role:        "",
						Source:      "",
						Environment: "",
						Contact:     "",
					},
					&types.Project{
						Project:     "ns-devops-automation-integration",
						Role:        "",
						Source:      "",
						Environment: "",
						Contact:     "",
					},
				},
				groups:               []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				username:             "foo",
				email:                "foo@bar.baz",
				hasAdminAccess:       true,
				hasApplicationAccess: false,
				hasOpsAccess:         false,
				hasViewerAccess:      false,
				hasServiceAccess:     false,
				issuer:               &TokenIssuer{EcdsaPrivate: &ecdsa.PrivateKey{}, EcdsaPublic: &ecdsa.PublicKey{}, TokenDuration: "4h", Locator: utils.KubiLocatorIntranet},
			},
			expected: want{
				err:    nil,
				auths:  []string{},
				groups: []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				user:   "foo",
			},
		},
		{
			name: "Appops user does not have projects",
			args: args{
				auths: []*types.Project{
					&types.Project{
						Project:     "ns-development",
						Role:        "",
						Source:      "",
						Environment: "",
						Contact:     "",
					},
					&types.Project{
						Project:     "ns-devops-automation-integration",
						Role:        "",
						Source:      "",
						Environment: "",
						Contact:     "",
					},
				},
				groups:               []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				username:             "foo",
				email:                "foo@bar.baz",
				hasAdminAccess:       false,
				hasApplicationAccess: false,
				hasOpsAccess:         true,
				hasViewerAccess:      false,
				hasServiceAccess:     false,
				issuer:               &TokenIssuer{EcdsaPrivate: &ecdsa.PrivateKey{}, EcdsaPublic: &ecdsa.PublicKey{}, TokenDuration: "4h", Locator: utils.KubiLocatorIntranet},
			},
			expected: want{
				err:    nil,
				auths:  []string{},
				groups: []string{"DL_ns-development_admin", "DL_ns-devops-automation-integration_admin", "babar"},
				user:   "foo",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, gotErr := generateUserClaims(tt.args.auths, tt.args.groups, tt.args.username, tt.args.email, tt.args.hasAdminAccess, tt.args.hasApplicationAccess, tt.args.hasOpsAccess, tt.args.hasViewerAccess, tt.args.hasServiceAccess, tt.args.issuer)
			if gotErr != nil {
				assert.Equal(t, gotErr, tt.expected.err)
			}
			assert.Equalf(t, gotToken.User, tt.expected.user, "generateUserClaims(%v, %v, %v, %v, %v, %v, %v, %v, %v, %v)", tt.args.auths, tt.args.groups, tt.args.username, tt.args.email, tt.args.hasAdminAccess, tt.args.hasApplicationAccess, tt.args.hasOpsAccess, tt.args.hasViewerAccess, tt.args.hasServiceAccess, tt.args.issuer)
			if !reflect.DeepEqual(gotToken.Groups, tt.expected.groups) {
				t.Errorf("generateUserClaims() got = %v, want %v", gotToken.Groups, tt.expected.groups)
			}

			var listAuths []string
			for _, projectAuthName := range gotToken.Auths {
				listAuths = append(listAuths, projectAuthName.Project)
			}

			sort.Strings(listAuths)
			sort.Strings(tt.expected.auths)
			if !slices.Equal(listAuths, tt.expected.auths) {
				t.Errorf("generateUserClaims() got = %v, want %v", gotToken.Auths, tt.expected.auths)
			}
		})
	}
}
