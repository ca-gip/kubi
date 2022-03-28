package utils

import (
	"context"
	"errors"
	corev1 "k8s.io/api/core/v1"

	"github.com/ca-gip/kubi/pkg/types"
	"github.com/mitchellh/mapstructure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func MakeBlackWhitelist() (*types.BlackWhitelist, error) {

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientSet, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}

	api := clientSet.CoreV1()

	blacklistCM, errRB := api.ConfigMaps(Config.BlackWhitelistNamespace).Get(context.TODO(), "blackwhitelist", metav1.GetOptions{})
	if errRB != nil {
		Log.Info().Msg("Blacklist or Whitelist not present")
		return nil, nil
	}

	blackWhiteList := types.BlackWhitelist{}

	if err := mapstructure.Decode(blacklistCM.Data, &blackWhiteList); err != nil {

		event := &corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name: "Black&Whitelistfailed",
			},
			Reason:  "Black&Whitelistfailed",
			Message: "Cannot unmarshal json from black&white config map, you missing something, read the doc",
			Source:  corev1.EventSource{},
		}

		api.Events(Config.BlackWhitelistNamespace).Create(context.TODO(), event, metav1.CreateOptions{})

		errUnmarshal := errors.New("Cannot unmarshal black&white list")
		Log.Error().Err(errUnmarshal)
		return nil, errUnmarshal
	}

	return &blackWhiteList, nil

}
