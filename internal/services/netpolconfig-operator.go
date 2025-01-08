package services

import (
	"context"
	"fmt"
	"time"

	"github.com/ca-gip/kubi/internal/utils"
	v12 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	"github.com/ca-gip/kubi/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Watch NetworkPolicyConfig, which is a config object for namespace network bubble
// This CRD allow user to deploy global configuration for network configuration
// for update, the default network config is updated
// for deletion, it is automatically recreated
// for create, just create it
func WatchNetPolConfig() cache.Store {
	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return nil
	}

	v3, err := versioned.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return nil
	}

	watchlist := cache.NewFilteredListWatchFromClient(v3.CagipV1().RESTClient(), "networkpolicyconfigs", metav1.NamespaceAll, utils.DefaultWatchOptionModifier)

	resyncPeriod := 30 * time.Minute

	store, controller := cache.NewInformer(watchlist, &v12.NetworkPolicyConfig{}, resyncPeriod, cache.ResourceEventHandlerFuncs{
		AddFunc:    networkPolicyConfigCreated,
		DeleteFunc: networkPolicyConfigDelete,
		UpdateFunc: networkPolicyConfigUpdate,
	})

	go controller.Run(wait.NeverStop)

	return store
}

func networkPolicyConfigUpdate(old interface{}, new interface{}) {
	netpolconfig := new.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has changed, refreshing associated resources: networkpolicies, for all kubi's namespaces.", netpolconfig.Name)

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return
	}

	clientSet, err := versioned.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return
	}

	projects, err := clientSet.CagipV1().Projects().List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return
	}

	for _, project := range projects.Items {
		utils.Log.Info().Msgf("Operator: refresh network policy for %v", project.Name)
		if utils.Config.NetworkPolicy {
			generateNetworkPolicy(project.Name, netpolconfig)
		}
	}

}

func networkPolicyConfigCreated(obj interface{}) {
	netpolconfig := obj.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has been created, refreshing associated resources: networkpolicies, for all kubi's namespaces.", netpolconfig.Name)

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return
	}

	clientSet, err := versioned.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return
	}

	projects, err := clientSet.CagipV1().Projects().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return
	}

	for _, project := range projects.Items {
		utils.Log.Info().Msgf("Operator: refresh network policy for %v", project.Name)
		if utils.Config.NetworkPolicy {
			generateNetworkPolicy(project.Name, netpolconfig)
		}
	}
}

func networkPolicyConfigDelete(obj interface{}) {
	netpolconfig := obj.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has been deleted, please delete networkpolicies for all kubi's namespaces. Be careful !", netpolconfig.Name)
}
