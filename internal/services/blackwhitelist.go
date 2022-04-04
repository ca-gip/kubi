package services

import (
	"context"
	"strings"

	"github.com/ca-gip/kubi/internal/utils"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/ca-gip/kubi/pkg/types"
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

func CreateBlackWhitelistEvent(errEvent string, api v1.CoreV1Interface) error {

	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name: "Black&Whitelistfailed",
		},
		Reason:  "Black&Whitelistfailed",
		Message: errEvent,
		Source:  corev1.EventSource{},
	}

	if _, err := api.Events(utils.Config.BlackWhitelistNamespace).Create(context.TODO(), event, metav1.CreateOptions{}); err != nil {
		utils.Log.Error().Err(err)
		return err
	}

	return nil
}

func MakeBlackWhitelist(blackWhiteCMData map[string]string) types.BlackWhitelist {

	blackWhiteList := types.BlackWhitelist{
		Blacklist: strings.Split(blackWhiteCMData["blacklist"], ","),
		Whitelist: strings.Split(blackWhiteCMData["whitelist"], ","),
	}

	return blackWhiteList

}
