package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"

	"github.com/ca-gip/kubi/internal/utils"
	cagipv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	v13 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	podSecurity "k8s.io/pod-security-admission/api"
)

// todo: remove namespace: high cardinality, no value
var NamespaceCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_namespace_creation",
	Help: "Number of namespace created",
}, []string{"status", "name"})

// generateNamespace from a name
// If it doesn't exist or the number of labels is different from what it should be
func generateNamespace(project *cagipv1.Project) (err error) {
	if project == nil {
		return errors.New("project reference is empty")
	}

	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	ns, errNs := api.Namespaces().Get(context.TODO(), project.Name, metav1.GetOptions{})

	isNsUptodate := reflect.DeepEqual(ns.Labels, generateNamespaceLabels(project))

	switch {
	case errNs != nil && kerror.IsNotFound(errNs):
		slog.Info("creating namespace", "namespace", project.Name)
		return createNamespace(project, api)
	case errNs != nil:
		return errNs
	case errNs == nil && !isNsUptodate:
		slog.Info("updating namespace", "namespace", project.Name)
		return updateExistingNamespace(project, api)
	default:
		return nil
	}
}

func createNamespace(project *cagipv1.Project, api v13.CoreV1Interface) error {
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Namespace",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   project.Name,
			Labels: generateNamespaceLabels(project),
		},
	}
	_, err := api.Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to api call create namespace on ns %v, %v", project.Name, err)
	}
	return err
}

func updateExistingNamespace(project *cagipv1.Project, api v13.CoreV1Interface) error {
	ns, errns := api.Namespaces().Get(context.TODO(), project.Name, metav1.GetOptions{})
	if errns != nil {
		return fmt.Errorf("k8s api error while fetching ns %v for its update, %v", ns, errns)
	}

	ns.Name = project.Name
	ns.ObjectMeta.Labels = generateNamespaceLabels(project)

	_, err := api.Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("k8s api error while updating ns %v, %v", ns, errns)
	}
	return nil
}

// Join two maps by value copy non-recursively
func union(a map[string]string, b map[string]string) map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// Generate CustomLabels that should be applied on Kubi's Namespaces
func generateNamespaceLabels(project *cagipv1.Project) (labels map[string]string) {

	defaultLabels := map[string]string{
		"name":                               project.Name,
		"type":                               "customer",
		"creator":                            "kubi",
		"environment":                        project.Spec.Environment,
		"pod-security.kubernetes.io/enforce": GetPodSecurityStandardName(project.Name),
		"pod-security.kubernetes.io/warn":    string(utils.Config.PodSecurityAdmissionWarning),
		"pod-security.kubernetes.io/audit":   string(utils.Config.PodSecurityAdmissionAudit),
	}
	// Todo: Decide whether this is still worth a separate function for testability.
	return union(defaultLabels, utils.Config.CustomLabels)
}

func GetPodSecurityStandardName(namespace string) string {
	if slices.Contains(utils.Config.PrivilegedNamespaces, namespace) {
		slog.Warn("namespace is labeled as privileged", "namespace", namespace)
		return string(podSecurity.LevelPrivileged)
	}
	return string(utils.Config.PodSecurityAdmissionEnforcement)
}
