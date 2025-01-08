package services

import (
	"context"
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	v14 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/rest"
)

// GenerateRolebinding from tupple
// If exists, nothing is done, only creating !
func GenerateUserRoleBinding(namespace string, role string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.RbacV1()

	roleBinding(fmt.Sprintf("%s-%s", "namespaced", role), api, namespace, subjectAdmin(namespace, role))
	roleBinding("view", api, namespace, subjectView())
}

func subjectView() []v1.Subject {
	subjectView := []v1.Subject{
		{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Group",
			Name:     utils.ApplicationViewer,
		},
	}
	return subjectView
}

func subjectAdmin(namespace string, role string) []v1.Subject {
	subjectAdmin := []v1.Subject{
		{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Group",
			Name:     fmt.Sprintf("%s-%s", namespace, role),
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
	}
	return subjectAdmin
}

func roleBinding(roleBindingName string, api v14.RbacV1Interface, namespace string, subjectAdmin []v1.Subject) {

	newRoleBinding := v1.RoleBinding{
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleBindingName,
		},
		Subjects: subjectAdmin,
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: namespace,
			Labels: map[string]string{
				"name":    roleBindingName,
				"creator": "kubi",
				"version": "v3",
			},
		},
	}

	_, errRB := api.RoleBindings(namespace).Get(context.TODO(), roleBindingName, metav1.GetOptions{})
	if errRB != nil {
		_, err := api.RoleBindings(namespace).Create(context.TODO(), &newRoleBinding, metav1.CreateOptions{})
		if err != nil {
			utils.RoleBindingsCreation.WithLabelValues("error", namespace, roleBindingName).Inc()
			utils.Log.Error().Msg(err.Error())
		}
		utils.ServiceAccountCreation.WithLabelValues("created", namespace, roleBindingName).Inc()
		utils.Log.Info().Msgf("Rolebinding %v has been created for namespace %v and roleBindingName %v", roleBindingName, namespace, roleBindingName)
		return
	}
	_, err := api.RoleBindings(namespace).Update(context.TODO(), &newRoleBinding, metav1.UpdateOptions{})
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		utils.RoleBindingsCreation.WithLabelValues("error", namespace, roleBindingName).Inc()
		return
	}
	utils.RoleBindingsCreation.WithLabelValues("updated", namespace, roleBindingName).Inc()
	utils.Log.Info().Msgf("rolebinding %v has been updated for namespace %v and roleBindingName %v", roleBindingName, namespace, roleBindingName)
}

func GenerateAppRoleBinding(namespace string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.RbacV1()

	_, errRB := api.RoleBindings(namespace).Get(context.TODO(), utils.KubiRoleBindingAppName, metav1.GetOptions{})

	newRoleBinding := v1.RoleBinding{
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     utils.KubiClusterRoleAppName,
		},
		Subjects: []v1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      utils.KubiServiceAccountAppName,
				Namespace: namespace,
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.KubiRoleBindingAppName,
			Namespace: namespace,
			Labels: map[string]string{
				"name":    utils.KubiRoleBindingAppName,
				"creator": "kubi",
				"version": "v3",
			},
		},
	}

	if errRB != nil {
		_, err := api.RoleBindings(namespace).Create(context.TODO(), &newRoleBinding, metav1.CreateOptions{})
		if err != nil {
			utils.Log.Error().Msg(err.Error())
			utils.RoleBindingsCreation.WithLabelValues("error", namespace, utils.KubiServiceAccountAppName).Inc()
			return
		}
		utils.RoleBindingsCreation.WithLabelValues("created", namespace, utils.KubiServiceAccountAppName).Inc()
		utils.Log.Info().Msgf("Rolebinding %v has been created for namespace %v", utils.KubiServiceAccountAppName, namespace)
		return
	}

	_, err := api.RoleBindings(namespace).Update(context.TODO(), &newRoleBinding, metav1.UpdateOptions{})
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		utils.RoleBindingsCreation.WithLabelValues("error", namespace, utils.KubiServiceAccountAppName).Inc()
		return
	}
	utils.RoleBindingsCreation.WithLabelValues("updated", namespace, utils.KubiServiceAccountAppName).Inc()
	utils.Log.Info().Msgf("Rolebinding %v has been update for namespace %v", utils.KubiServiceAccountAppName, namespace)
}

func GenerateDefaultRoleBinding(namespace string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.RbacV1()

	_, errRB := api.RoleBindings(namespace).Get(context.TODO(), utils.KubiRoleBindingDefaultName, metav1.GetOptions{})

	newRoleBinding := v1.RoleBinding{
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     utils.Config.DefaultPermission,
		},
		Subjects: []v1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      utils.KubiServiceAccountDefaultName,
				Namespace: namespace,
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.KubiRoleBindingDefaultName,
			Namespace: namespace,
			Labels: map[string]string{
				"name":    utils.KubiRoleBindingDefaultName,
				"creator": "kubi",
				"version": "v3",
			},
		},
	}

	if errRB != nil {
		_, err := api.RoleBindings(namespace).Create(context.TODO(), &newRoleBinding, metav1.CreateOptions{})
		if err != nil {
			utils.Log.Error().Msg(err.Error())
			utils.RoleBindingsCreation.WithLabelValues("error", namespace, utils.KubiServiceAccountAppName).Inc()
			return
		}
		utils.Log.Info().Msgf("Rolebinding %v has been created for namespace %v", utils.KubiServiceAccountAppName, namespace)
		utils.RoleBindingsCreation.WithLabelValues("created", namespace, utils.KubiServiceAccountAppName).Inc()
		return
	}
	_, err := api.RoleBindings(namespace).Update(context.TODO(), &newRoleBinding, metav1.UpdateOptions{})
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		utils.RoleBindingsCreation.WithLabelValues("error", namespace, utils.KubiServiceAccountAppName).Inc()
		return
	}
	utils.Log.Info().Msgf("Rolebinding %v has been update for namespace %v", utils.KubiServiceAccountAppName, namespace)
	utils.RoleBindingsCreation.WithLabelValues("updated", namespace, utils.KubiServiceAccountAppName).Inc()
}
