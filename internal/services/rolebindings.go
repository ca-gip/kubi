package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ca-gip/kubi/internal/utils"
	cagipv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
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
	var validSubjects []v1.Subject
	for _, subject := range subjects {
		if subject.Name != "" {
			validSubjects = append(validSubjects, subject)
		}
	}
	return &v1.RoleBinding{
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole,
		},
		Subjects: validSubjects,
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
func generateRoleBindings(project *cagipv1.Project, defaultServiceAccountRole string) error {
	var errors []error

	namespace := project.Name
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
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     project.Spec.SourceEntity, // the equivalent of $namespace-admin
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     ToSubject(utils.Config.Ldap.AppMasterGroupBase), // the equivalent of application master (appops)
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     ToSubject(utils.Config.Ldap.CustomerOpsGroupBase), // the equivalent of application master (customerops)
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     ToSubject(utils.Config.Ldap.OpsMasterGroupBase), // the equivalent of ops master
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
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     ToSubject(utils.Config.Ldap.ViewerGroupBase),
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
			errors = append(errors, fmt.Errorf("could not handle rolebinding %v/%v, %v", namespace, rb.name, err))
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf("encountered the following errors in rolebindings create or update: %v", errors)
	}
	return nil
}

// Quick and hacky way to parse DN from config, without having to load an ldap parser or doing any query
// if not valid, return an empty string, which does not get applied in the list of subjects, as:
// 1. it's not valid to not have a name
// 2. We check whether we have a name in the generation of the rolebinding object.
func ToSubject(DN string) string {
	p := regexp.MustCompile(("CN=([^,]+)")).FindStringSubmatch(DN)
	if len(p) > 1 {
		return strings.TrimSpace(p[1])
	}
	return ""
}
