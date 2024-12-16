package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ca-gip/kubi/internal/utils"
	"k8s.io/api/authentication/v1beta1"
)

// Authenticate service for kubernetes Api Server
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication
func AuthenticateHandler(issuer *TokenIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var code int
		var tokenStatus error

		bodyString, err := io.ReadAll(r.Body)
		if err != nil {
			utils.Log.Error().Err(err)
		}
		tokenReview := v1beta1.TokenReview{}
		err = json.Unmarshal(bodyString, &tokenReview)
		if err != nil {
			utils.Log.Error().Msg(err.Error())
		}

		token, err := issuer.CurrentJWT(tokenReview.Spec.Token)
		if err == nil {
			tokenStatus = issuer.VerifyToken(tokenReview.Spec.Token)
		}

		if err != nil || tokenStatus != nil {
			resp := v1beta1.TokenReview{
				Status: v1beta1.TokenReviewStatus{
					Authenticated: false,
				},
			}
			code = http.StatusUnauthorized
			w.WriteHeader(code)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		} else {
			utils.Log.Info().Msgf("Challenging token for user %v", token.User)

			var groups []string
			groups = append(groups, utils.AuthenticatedGroup)
			groups = append(groups, fmt.Sprintf(utils.KubiClusterRoleBindingReaderName))

			// Other ldap group are injected
			for _, auth := range token.Auths {
				groups = append(groups, fmt.Sprintf("%s-%s", auth.Namespace(), auth.Role))
			}

			if token.AdminAccess {
				groups = append(groups, utils.AdminGroup)
			}

			if token.OpsAccess {
				groups = append(groups, utils.OPSMaster)
			}

			if token.ApplicationAccess {
				groups = append(groups, utils.ApplicationMaster)
			}

			if token.ServiceAccess {
				groups = append(groups, utils.ServiceMaster)
			}

			if token.ViewerAccess {
				groups = append(groups, utils.ApplicationViewer)
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
			code = http.StatusOK
			w.WriteHeader(code)

			jwtTokenString, marshallError := json.Marshal(resp)
			if marshallError == nil {
				utils.Log.Debug().Msgf("%v", string(jwtTokenString))
			} else {
				utils.Log.Error().Msgf("Errot serializing json to token review: %s", marshallError.Error())
			}

			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				utils.Log.Error().Msg(err.Error())
			}

		}

	}

}
