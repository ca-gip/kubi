package services

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/ca-gip/kubi/internal/utils"
	"k8s.io/api/authentication/v1beta1"
)

const (
	AdminGroup    = "system:masters"
	ServiceMaster = "service:masters"
)

// Authenticate service for kubernetes Api Server
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication
func AuthenticateHandler(issuer *TokenIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		bodyString, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Info("error in request body", "error", err)
		}
		tokenReview := v1beta1.TokenReview{}
		err = json.Unmarshal(bodyString, &tokenReview)
		if err != nil {
			slog.Info("error unmarshalling token", "error", err)
		}

		token, err := issuer.VerifyToken(tokenReview.Spec.Token)

		if err != nil {
			resp := v1beta1.TokenReview{
				Status: v1beta1.TokenReviewStatus{
					Authenticated: false,
				},
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}

		slog.Debug("preparing access for user", "user", token.User)

		var groups []string
		groups = append(groups, utils.AuthenticatedGroup)

		// LEGACY GROUPS, only for comptability purposes
		// TODO: After this version of kubi is released, wait for a month (expiration
		// of the service token) and remove the following groups.
		// Ensure it is also done on the argocd's dex kubi plugin.
		groups = append(groups, fmt.Sprintf(utils.KubiClusterRoleBindingReaderName))

		for _, auth := range token.Auths {
			groups = append(groups, fmt.Sprintf("%s-%s", auth.Namespace(), auth.Role))
		}

		// Hard coded special groups
		if token.ServiceAccess {
			groups = append(groups, ServiceMaster)
		}

		if token.AdminAccess {
			groups = append(groups, AdminGroup)
		}

		if token.OpsAccess {
			groups = append(groups, utils.OPSMaster)
		}

		if token.ApplicationAccess {
			groups = append(groups, utils.ApplicationMaster)
		}

		if token.ViewerAccess {
			groups = append(groups, utils.ApplicationViewer)
		}

		// New Group mapping: In the future, we just expose the token's groups.
		// Filtering will be made solely on the kubi API server side in the future.
		groups = append(groups, token.Groups...)

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
		w.WriteHeader(http.StatusOK)

		jwtTokenString, marshallError := json.Marshal(resp)
		if marshallError != nil {
			slog.Error("Error serializing json to token review", "error", marshallError.Error(), "token", jwtTokenString)
		}

		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			slog.Error("cannot encode resp", "error", err)
		}

	}

}
