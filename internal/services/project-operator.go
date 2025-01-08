package services

import (
	"fmt"
	"strings"
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
func WatchProjects() cache.Store {
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

	watchlist := cache.NewFilteredListWatchFromClient(v3.CagipV1().RESTClient(), "projects", metav1.NamespaceAll, utils.DefaultWatchOptionModifier)
	resyncPeriod := 30 * time.Minute

	store, controller := cache.NewInformer(watchlist, &v12.Project{}, resyncPeriod, cache.ResourceEventHandlerFuncs{
		AddFunc:    projectCreated,
		DeleteFunc: projectDelete,
		UpdateFunc: projectUpdate,
	})

	go controller.Run(wait.NeverStop)

	return store
}

func projectUpdate(old interface{}, new interface{}) {
	newProject := new.(*v12.Project)
	utils.Log.Info().Msgf("Operator: the project %v has been updated, updating associated resources: namespace, networkpolicies.", newProject.Name)

	err := generateNamespace(newProject)
	if err != nil {
		utils.Log.Warn().Msgf("Unexpected error %s", err)
		return
	}

	if utils.Config.NetworkPolicy {
		generateNetworkPolicy(newProject.Name, nil)
	}
	// TODO: Refactor with a non static list of roles
	GenerateUserRoleBinding(newProject.Name, "admin")
	GenerateAppServiceAccount(newProject.Name)
	GenerateAppRoleBinding(newProject.Name)
	if !strings.EqualFold(utils.Config.DefaultPermission, "") {
		GenerateDefaultRoleBinding(newProject.Name)
	}

}

func projectCreated(obj interface{}) {
	project := obj.(*v12.Project)
	utils.Log.Info().Msgf("Operator: the project %v has been created, generating associated resources: namespace, networkpolicies.", project.Name)

	err := generateNamespace(project)
	if err != nil {
		utils.Log.Warn().Msgf("Unexpected error %s", err)
		return
	}

	if utils.Config.NetworkPolicy {
		generateNetworkPolicy(project.Name, nil)
	}

	// TODO: Refactor with a non static list of roles
	GenerateUserRoleBinding(project.Name, "admin")
	GenerateAppServiceAccount(project.Name)
	GenerateAppRoleBinding(project.Name)
	if !strings.EqualFold(utils.Config.DefaultPermission, "") {
		GenerateDefaultRoleBinding(project.Name)
	}

}

func projectDelete(obj interface{}) {
	project := obj.(*v12.Project)
	utils.Log.Info().Msgf("Operator: the project %v has been deleted, Kubi won't delete anything, please delete the namespace %v manualy", project.Name, project.Name)
}
