package services

import (
	"context"

	"github.com/ca-gip/kubi/internal/utils"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetBlackWhitelistCM(api v1.CoreV1Interface) (*corev1.ConfigMap, error) {

	blacklistCM, errRB := api.ConfigMaps(utils.Config.BlackWhitelistNamespace).Get(context.TODO(), "blackwhitelist", metav1.GetOptions{})
	if errRB != nil {
		utils.Log.Info().Msg("Blacklist or Whitelist not present")
		return nil, errRB
	}

	return blacklistCM, nil

}
