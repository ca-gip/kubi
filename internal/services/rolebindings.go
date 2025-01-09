package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	v1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	rbacv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/rest"
)

var RoleBindingsCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_rolebindings_creation",
	Help: "Number of role bindings created",
}, []string{"status", "target_namespace", "name"})

// generateRoleBinding is convenience function for readability, returning a properly formatted rolebinding object.
func newRoleBinding(name string, namespace string, clusterRole string, subjects []v1.Subject) *v1.RoleBinding {
	return &v1.RoleBinding{
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole,
		},
		Subjects: subjects,
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"name":    name,
				"creator": "kubi",
				"version": "v3",
			},
		},
	}
}

// createOrUpdateRoleBinding applies the roleBinding into the cluster?
func createOrUpdateRoleBinding(api rbacv1.RbacV1Interface, roleBinding *v1.RoleBinding) error {
	_, err := api.RoleBindings(roleBinding.ObjectMeta.Namespace).Get(context.TODO(), roleBinding.ObjectMeta.Name, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		RoleBindingsCreation.WithLabelValues("error", roleBinding.ObjectMeta.Namespace, roleBinding.ObjectMeta.Name).Inc()
		return fmt.Errorf("unknown error %v", err)
	}
	if err != nil && k8serrors.IsNotFound(err) {
		_, err := api.RoleBindings(roleBinding.ObjectMeta.Namespace).Create(context.TODO(), roleBinding, metav1.CreateOptions{})
		if err != nil {
			RoleBindingsCreation.WithLabelValues("error", roleBinding.ObjectMeta.Namespace, roleBinding.ObjectMeta.Name).Inc()
			return fmt.Errorf("error while creating new rolebinding %v/%v: %v", roleBinding.ObjectMeta.Namespace, roleBinding.ObjectMeta.Name, err)
		}
		RoleBindingsCreation.WithLabelValues("created", roleBinding.ObjectMeta.Namespace, roleBinding.ObjectMeta.Name).Inc()
		return err
	}
	// Exists, force update.
	if _, err := api.RoleBindings(roleBinding.ObjectMeta.Namespace).Update(context.TODO(), roleBinding, metav1.UpdateOptions{}); err != nil {
		RoleBindingsCreation.WithLabelValues("error", roleBinding.ObjectMeta.Namespace, roleBinding.ObjectMeta.Name).Inc()
		return fmt.Errorf("unable to update rolebinding %v/%v: %v", roleBinding.ObjectMeta.Namespace, roleBinding.ObjectMeta.Name, err)
	}
	RoleBindingsCreation.WithLabelValues("updated", roleBinding.ObjectMeta.Namespace, roleBinding.ObjectMeta.Name).Inc()
	return nil
}

// generateRoleBindings handles ALL the rolebindings for a namespace.
func generateRoleBindings(namespace string, defaultServiceAccountRole string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.RbacV1()

	roleBindings := []struct {
		name        string
		clusterRole string
		subjects    []v1.Subject
	}{
		{
			name:        "namespaced-admin",
			clusterRole: "namespaced-admin",
			subjects: []v1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     fmt.Sprintf("%s-%s", namespace, "admin"),
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     utils.ApplicationMaster,
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     utils.OPSMaster,
				},
			},
		},
		{
			name:        "view",
			clusterRole: "view",
			subjects: []v1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     utils.ApplicationViewer,
				},
			},
		},
		{
			name:        utils.KubiRoleBindingAppName,
			clusterRole: utils.KubiClusterRoleAppName,
			subjects: []v1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      utils.KubiServiceAccountAppName,
					Namespace: namespace,
				},
			},
		},
		{
			name:        utils.KubiRoleBindingDefaultName,
			clusterRole: defaultServiceAccountRole,
			subjects: []v1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      utils.KubiServiceAccountDefaultName,
					Namespace: namespace,
				},
			},
		},
	}
	for _, rb := range roleBindings {
		// For the rare (ancient!) case where the default clusterRole
		// was empty (before it was pod-reader). If we want to remove it, we can.
		if rb.clusterRole == "" {
			continue
		}
		err := createOrUpdateRoleBinding(api, newRoleBinding(rb.name, namespace, rb.clusterRole, rb.subjects))
		if err != nil {
			slog.Error(fmt.Sprintf("could not handle rolebinding %v/%v, %v", namespace, rb.name, err))
		}
	}
}
