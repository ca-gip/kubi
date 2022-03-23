package utils

import (
	"context"

	"github.com/ca-gip/kubi/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func MakeBlackWhitelist() (*types.Config, error) {

	kconfig, err := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	blacklistCM, errRB := api.ConfigMaps(Config.BlackWhitelistNamespace).Get(context.TODO(), "blackwhitelist", metav1.GetOptions{})
	if errRB != nil {
		utils.Log.Error().Msg(errRB.Error())
		return
	} else {
		utils.ProjectCreation.WithLabelValues("created", projectInfos.Project).Inc()
	}

	keys := make([]string, 0, len(blacklistCM.Data))
	for k := range blacklistCM.Data {
		keys = append(keys, k)
	}

	blackwhitelist := types.BlackWhitelist{
		Blacklist: keys["blacklist"],
		Whitelist: keys["whitelist"],
	}

}
