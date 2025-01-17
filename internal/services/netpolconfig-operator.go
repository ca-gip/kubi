package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/ca-gip/kubi/internal/utils"
	cagipv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
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
		slog.Error("failed to create in cluster config", "error", err)
		return nil
	}

	v3, err := versioned.NewForConfig(kconfig)
	if err != nil {
		slog.Error("failed to create kubernetes clientset", "error", err)
		return nil
	}

	watchlist := cache.NewFilteredListWatchFromClient(v3.CagipV1().RESTClient(), "networkpolicyconfigs", metav1.NamespaceAll, utils.DefaultWatchOptionModifier)

	resyncPeriod := 30 * time.Minute

	store, controller := cache.NewInformer(watchlist, &cagipv1.NetworkPolicyConfig{}, resyncPeriod, cache.ResourceEventHandlerFuncs{
		AddFunc:    networkPolicyConfigCreated,
		DeleteFunc: networkPolicyConfigDeleted,
		UpdateFunc: networkPolicyConfigUpdated,
	})

	go controller.Run(wait.NeverStop)

	return store
}
func networkPolicyConfigCreated(obj interface{}) {
	netpolconfig := obj.(*cagipv1.NetworkPolicyConfig)
	slog.Info("network config has been created, refreshing associated resources", "networkConfig", netpolconfig.Name)
	createOrUpdateNetpols(netpolconfig)
}

func networkPolicyConfigUpdated(old interface{}, new interface{}) {
	netpolconfig := new.(*cagipv1.NetworkPolicyConfig)
	slog.Info("network config has been updated, refreshing associated resources", "networkConfig", netpolconfig.Name)
	createOrUpdateNetpols(netpolconfig)
}

func createOrUpdateNetpols(netpolconfig *cagipv1.NetworkPolicyConfig) {

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("failed to create in cluster config", "error", err)
		return
	}

	clientSet, err := versioned.NewForConfig(kconfig)
	if err != nil {
		slog.Error("failed to create kubernetes clientset", "error", err)
		return
	}

	projects, err := clientSet.CagipV1().Projects().List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		slog.Error("failed to list projects", "error", err)
		return
	}

	for _, project := range projects.Items {
		slog.Info("refreshing network policy for project", "project", project.Name)
		err := generateNetworkPolicy(project.Name, netpolconfig)
		if err != nil {
			slog.Error("cannot generate network policy", "namespace", project.Name, "error", err)
			NetworkPolicyCreation.WithLabelValues("error", project.Name, utils.KubiDefaultNetworkPolicyName).Inc()
		}
		NetworkPolicyCreation.WithLabelValues("updated", project.Name, utils.KubiDefaultNetworkPolicyName).Inc()
	}

}

func networkPolicyConfigDeleted(obj interface{}) {
	netpolconfig := obj.(*cagipv1.NetworkPolicyConfig)
	slog.Info("network config has been deleted, please delete network policies manually", "networkConfig", netpolconfig.Name)
}
