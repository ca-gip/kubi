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
	kubernetes "k8s.io/client-go/kubernetes"
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

	store, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchlist,
		ResyncPeriod:  resyncPeriod,
		ObjectType:    &cagipv1.Project{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    projectCreated,
			DeleteFunc: projectDeleted,
			UpdateFunc: projectUpdated,
		},
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
		ServiceAccountCreation.WithLabelValues("error", project.Name, utils.KubiServiceAccountAppName).Inc()
		return
	}
	slog.Debug("service Account created", "object", utils.KubiServiceAccountAppName, "namespace", project.Name)
	ServiceAccountCreation.WithLabelValues("ok", project.Name, utils.KubiServiceAccountAppName).Inc()

	if err := generateRoleBindings(project, utils.Config.DefaultPermission); err != nil {
		slog.Error("generate role binding error", "error", err)
		RoleBindingsCreation.WithLabelValues("error", project.Name, "rolebindings").Inc()
		return
	}
	slog.Debug("role bindings created", "namespace", project.Name)
	RoleBindingsCreation.WithLabelValues("ok", project.Name, "rolebindings").Inc()

}

func projectDeleted(obj interface{}) {
	project := obj.(*cagipv1.Project)
	slog.Info("Operator: a project was deleted, cleaning up associated resources", "namespace", project.Name)
	deleteProjectResources(project)
}

func deleteProjectResources(project *cagipv1.Project) {
	// Delete role bindings first
	if err := deleteRoleBindings(project.Name); err != nil {
		slog.Error("failed to delete role bindings", "namespace", project.Name, "error", err)
		RoleBindingsCreation.WithLabelValues("delete_error", project.Name, "rolebindings").Inc()
	} else {
		slog.Debug("role bindings deleted", "namespace", project.Name)
		RoleBindingsCreation.WithLabelValues("deleted", project.Name, "rolebindings").Inc()
	}

	// Delete service account
	if err := deleteAppServiceAccount(project.Name); err != nil {
		slog.Error("failed to delete service account", "namespace", project.Name, "error", err)
		ServiceAccountCreation.WithLabelValues("delete_error", project.Name, utils.KubiServiceAccountAppName).Inc()
	} else {
		slog.Debug("service account deleted", "object", utils.KubiServiceAccountAppName, "namespace", project.Name)
		ServiceAccountCreation.WithLabelValues("deleted", project.Name, utils.KubiServiceAccountAppName).Inc()
	}

	// Delete network policy if enabled
	if utils.Config.NetworkPolicy {
		if err := deleteNetworkPolicy(project.Name); err != nil {
			slog.Error("failed to delete network policy", "namespace", project.Name, "error", err)
			NetworkPolicyCreation.WithLabelValues("delete_error", project.Name, utils.KubiDefaultNetworkPolicyName).Inc()
		} else {
			slog.Debug("network policy deleted", "object", utils.KubiDefaultNetworkPolicyName, "namespace", project.Name)
			NetworkPolicyCreation.WithLabelValues("deleted", project.Name, utils.KubiDefaultNetworkPolicyName).Inc()
		}
	}

	// Delete namespace last
	if err := deleteNamespace(project.Name); err != nil {
		slog.Error("failed to delete namespace", "namespace", project.Name, "error", err)
		NamespaceCreation.WithLabelValues("delete_error", project.Name).Inc()
	} else {
		slog.Debug("namespace deleted", "namespace", project.Name)
		NamespaceCreation.WithLabelValues("deleted", project.Name).Inc()
	}
}

func deleteNamespace(namespaceName string) error {
	kconfig, _ := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return err
	}

	return clientSet.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{})
}

func deleteAppServiceAccount(namespaceName string) error {
	kconfig, _ := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return err
	}

	return clientSet.CoreV1().ServiceAccounts(namespaceName).Delete(context.TODO(), utils.KubiServiceAccountAppName, metav1.DeleteOptions{})
}

func deleteNetworkPolicy(namespaceName string) error {
	kconfig, _ := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return err
	}

	return clientSet.NetworkingV1().NetworkPolicies(namespaceName).Delete(context.TODO(), utils.KubiDefaultNetworkPolicyName, metav1.DeleteOptions{})
}

func deleteRoleBindings(namespaceName string) error {
	kconfig, _ := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return err
	}

	// Delete all role bindings in the namespace that were created by Kubi
	return clientSet.RbacV1().RoleBindings(namespaceName).DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{
		LabelSelector: "kubi.ca-gip.com/managed=true",
	})
}

