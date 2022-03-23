package utils

import (
	"context"

	"github.com/ca-gip/kubi/pkg/types"
	"github.com/mitchellh/mapstructure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func MakeBlackWhitelist() error {

	kconfig, err := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	blacklistCM, errRB := api.ConfigMaps(Config.BlackWhitelistNamespace).Get(context.TODO(), "blackwhitelist", metav1.GetOptions{})
	if errRB != nil {
		Log.Error().Msg(errRB.Error())
		return errRB
	}

	blackwhitelist := types.BlackWhitelist{}

	mapstructure.Decode(blacklistCM.Data, &blackwhitelist)

	return nil

}
