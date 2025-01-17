package services

import (
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
func WatchProjects() cache.Store {
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

	watchlist := cache.NewFilteredListWatchFromClient(v3.CagipV1().RESTClient(), "projects", metav1.NamespaceAll, utils.DefaultWatchOptionModifier)
	resyncPeriod := 30 * time.Minute

	store, controller := cache.NewInformer(watchlist, &cagipv1.Project{}, resyncPeriod, cache.ResourceEventHandlerFuncs{
		AddFunc:    projectCreated,
		DeleteFunc: projectDeleted,
		UpdateFunc: projectUpdated,
	})

	go controller.Run(wait.NeverStop)

	return store
}
func projectCreated(obj interface{}) {
	project := obj.(*cagipv1.Project)
	slog.Info("project has been created, creating associated resources", "project", project.Name)
	createOrUpdateProjectResources(project)
}

func projectUpdated(old interface{}, new interface{}) {
	project := new.(*cagipv1.Project)
	slog.Info("project has been updated, creating associated resources", "project", project.Name)
	createOrUpdateProjectResources(project)
}

func projectDeleted(obj interface{}) {
	project := obj.(*cagipv1.Project)
	slog.Warn("Operator: a project was deleted, Kubi won't delete anything, please delete the namespace manualy", "namespace", project.Name)
}

func createOrUpdateProjectResources(project *cagipv1.Project) {

	if err := generateNamespace(project); err != nil {
		slog.Error("generate namespace failed", "error", err)
		NamespaceCreation.WithLabelValues("error", project.Name).Inc()
		return
	}
	slog.Debug("namespace created", "namespace", project.Name)
	NamespaceCreation.WithLabelValues("ok", project.Name).Inc()

	// TODO: Get rid of the guard, and automatically add netpol
	if utils.Config.NetworkPolicy {
		err := generateNetworkPolicy(project.Name, nil)
		if err != nil {
			slog.Error("cannot generate network policy", "namespace", project.Name, "error", err)
			NetworkPolicyCreation.WithLabelValues("error", project.Name, utils.KubiDefaultNetworkPolicyName).Inc()
		}
		slog.Debug("network policy created", "object", utils.KubiDefaultNetworkPolicyName, "namespace", project.Name)
		NetworkPolicyCreation.WithLabelValues("updated", project.Name, utils.KubiDefaultNetworkPolicyName).Inc()
	}

	if err := GenerateAppServiceAccount(project.Name); err != nil {
		slog.Error("generate service account error", "error", err)
		ServiceAccountCreation.WithLabelValues("error", project.Name).Inc()
		return
	}
	slog.Debug("service Account created", "object", utils.KubiServiceAccountAppName, "namespace", project.Name)
	ServiceAccountCreation.WithLabelValues("ok", project.Name).Inc()

	if err := generateRoleBindings(project, utils.Config.DefaultPermission); err != nil {
		slog.Error("generate role binding error", "error", err)
		RoleBindingsCreation.WithLabelValues("error", project.Name).Inc()
		return
	}
	slog.Debug("role bindings created", "namespace", project.Name)
	RoleBindingsCreation.WithLabelValues("ok", project.Name).Inc()

}
