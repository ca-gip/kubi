package services

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/ca-gip/kubi/internal/utils"
	cagipv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	"github.com/ca-gip/kubi/pkg/generated/clientset/versioned"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	podSecurity "k8s.io/pod-security-admission/api"
)

// todo: remove namespace: high cardinality, no value
var NamespaceCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_namespace_creation",
	Help: "Number of namespace created",
}, []string{"status", "name"})

// generateNamespace from a name
// If it doesn't exist or the number of labels is different from what it should be

func WatchNamespaces() {
	kconfig, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("failed to create in cluster config", "error", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		slog.Error("failed to create kubernetes clientset", "error", err)
		return
	}

	cagipProjectClient, err := versioned.NewForConfig(kconfig)
	if err != nil {
		slog.Error("failed to create cagip projects clientset", "error", err)
		return
	}
	tweakListOptions := func(options *metav1.ListOptions) {
		options.LabelSelector = "creator=kubi"
	}

	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 10*time.Minute,
		informers.WithTweakListOptions(tweakListOptions))

	nsInformer := factory.Core().V1().Namespaces()
	nsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    nsCreated(cagipProjectClient),
		DeleteFunc: nsDeleted(cagipProjectClient),
		UpdateFunc: nsUpdated(cagipProjectClient),
	})

	stopCh := make(chan struct{})
	defer close(stopCh)
	factory.Start(stopCh)

	// Wait for cache sync
	if !cache.WaitForCacheSync(stopCh, nsInformer.Informer().HasSynced) {
		panic("failed to sync cache")
	}

	fmt.Println("Informer synced, watching for ns changes...")

	// Keep running
	<-stopCh
}

// Generate CustomLabels that should be applied on Kubi's Namespaces
func generateNamespaceLabels(project *cagipv1.Project) (labels map[string]string) {
	nsLabels := map[string]string{
		"name":                               project.Name,
		"type":                               "customer",
		"creator":                            "kubi",
		"environment":                        project.Spec.Environment,
		"pod-security.kubernetes.io/enforce": GetPodSecurityStandardName(project.Name),
		"pod-security.kubernetes.io/warn":    string(utils.Config.PodSecurityAdmissionWarning),
		"pod-security.kubernetes.io/audit":   string(utils.Config.PodSecurityAdmissionAudit),
	}
	// Todo: Decide whether this is still worth a separate function for testability.
	maps.Copy(nsLabels, utils.Config.CustomLabels)
	return nsLabels
}

func GetPodSecurityStandardName(namespace string) string {
	if slices.Contains(utils.Config.PrivilegedNamespaces, namespace) {
		slog.Warn("namespace is labeled as privileged", "namespace", namespace)
		return string(podSecurity.LevelPrivileged)
	}
	return string(utils.Config.PodSecurityAdmissionEnforcement)
}

func nsCreated(cagipProjectClientset *versioned.Clientset) func(obj any) {

	return func(obj any) {
		ns := obj.(*corev1.Namespace)
		slog.Info("project ns has been created , creating associated resources", "ns", ns.Name)
		project, err := cagipProjectClientset.CagipV1().Projects().Get(context.Background(), ns.Name, metav1.GetOptions{})
		if err != nil {
			slog.Error("failed to get projects", "error", err)
			return
		}
		createOrUpdateProjectResources(project)
	}
}

func nsUpdated(cagipProjectClientset *versioned.Clientset) func(old any, new any) {
	return func(old any, new any) {
		ns := new.(*corev1.Namespace)
		slog.Info("project ns has been updated, creating associated resources", "ns", ns.Name)
		project, err := cagipProjectClientset.CagipV1().Projects().Get(context.Background(), ns.Name, metav1.GetOptions{})
		if err != nil {
			slog.Error("failed to get projects", "error", err)
			return
		}
		createOrUpdateProjectResources(project)
	}
}

func nsDeleted(cagipProjectClientset *versioned.Clientset) func(obj any) {

	return func(obj any) {
		ns := obj.(*corev1.Namespace)
		slog.Info("project ns has been deleted , creating associated resources", "ns", ns.Name)
		err := cagipProjectClientset.CagipV1().Projects().Delete(context.Background(), ns.Name, metav1.DeleteOptions{})
		if err != nil {
			slog.Error("failed to delete project", "error", err, "project", ns.Name)
			return
		}
	}
}
