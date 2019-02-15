package services

import (
	"encoding/json"
	"fmt"
	"github.com/ca-gip/kubi/internal/utils"
	"io/ioutil"
	"k8s.io/api/authentication/v1beta1"
	"net/http"
)

// Authenticate service for kubernetes Api Server
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication
func AuthenticateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var code int

		bodyString, err := ioutil.ReadAll(r.Body)
		if err != nil {
			utils.Log.Error().Err(err)
		}
		tokenReview := v1beta1.TokenReview{}
		err = json.Unmarshal(bodyString, &tokenReview)
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
			code = http.StatusUnauthorized
			w.WriteHeader(code)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		} else {
			utils.Log.Info().Msgf("Challenging token for user %v", token.User)

			groups := []string{}
			groups = append(groups, utils.UnauthenticatedGroup)
			groups = append(groups, fmt.Sprintf(utils.KubiClusterRoleBindingReaderName))

			// Other ldap group are injected
			for _, auth := range token.Auths {
				groups = append(groups, fmt.Sprintf("%s-%s", auth.Namespace, auth.Role))
			}
			if token.AdminAccess {
				groups = append(groups, utils.KubiClusterRoleAdminBindingName)
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
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				utils.Log.Error().Msg(err.Error())
			}

		}

	}

}
