package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/ca-gip/kubi/internal/utils"
	v12 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	v13 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	podSecurity "k8s.io/pod-security-admission/api"
)

// generateNamespace from a name
// If it doesn't exist or the number of labels is different from what it should be
func generateNamespace(project *v12.Project) (err error) {
	if project == nil {
		return errors.New("project reference is empty")
	}

	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	ns, errNs := api.Namespaces().Get(context.TODO(), project.Name, metav1.GetOptions{})

	if kerror.IsNotFound(errNs) {
		err = createNamespace(project, api)
	} else if errNs == nil && !reflect.DeepEqual(ns.Labels, generateNamespaceLabels(project)) {
		err = updateExistingNamespace(project, api)
	} else {
		utils.NamespaceCreation.WithLabelValues("ok", project.Name).Inc()
	}
	return
}

func createNamespace(project *v12.Project, api v13.CoreV1Interface) error {
	utils.Log.Info().Msgf("Creating ns %v", project.Name)
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
		utils.Log.Error().Err(err)
		utils.NamespaceCreation.WithLabelValues("error", project.Name).Inc()
	} else {
		utils.NamespaceCreation.WithLabelValues("created", project.Name).Inc()
	}
	return err
}

func updateExistingNamespace(project *v12.Project, api v13.CoreV1Interface) error {
	utils.Log.Info().Msgf("Updating ns %v", project.Name)

	ns, errns := api.Namespaces().Get(context.TODO(), project.Name, metav1.GetOptions{})
	if errns != nil {
		msgError := fmt.Errorf("could not get namespace in updating ns in updateExistingNamespace() %v", errns)
		utils.Log.Error().Err(msgError)
		return msgError
	}

	ns.Name = project.Name
	ns.ObjectMeta.Labels = generateNamespaceLabels(project)

	_, err := api.Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		msgError := fmt.Errorf("could not update ns in updateExistingNamespace() %v", errns)
		utils.Log.Error().Err(msgError)
		utils.NamespaceCreation.WithLabelValues("error", project.Name).Inc()
		return msgError
	}

	utils.NamespaceCreation.WithLabelValues("updated", project.Name).Inc()

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
func generateNamespaceLabels(project *v12.Project) (labels map[string]string) {

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
		utils.Log.Warn().Msgf("Namespace %v is labeled as privileged", namespace)
		return string(podSecurity.LevelPrivileged)
	}
	return string(utils.Config.PodSecurityAdmissionEnforcement)
}
