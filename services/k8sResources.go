package services

import (
	"fmt"
	"intomy.land/kubi/types"
	"intomy.land/kubi/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
)

// Handler to regenerate all resources created by kubi
func RefreshK8SResources(w http.ResponseWriter, _ *http.Request) {

	w.WriteHeader(http.StatusAccepted)
	err := GenerateResourcesFromLdapGroups()
	if err != nil {
		utils.Log.Error().Err(err)
	}
}

// Generate Namespaces and Rolebinding from Ldap groups
func GenerateResourcesFromLdapGroups() error {
	groups, err := utils.LdapClient().GetGroups()
	if err != nil {
		return err
	}
	auths := GetUserNamespaces(groups)
	GenerateNamespaces(auths)
	GenerateRoleBindings(auths)
	return nil
}

// A loop wrapper for GenerateRoleBinding
// splitted for unit test !
func GenerateRoleBindings(context []*types.AuthJWTTupple) {
	for _, auth := range context {
		GenerateRoleBinding(auth)
	}
}

// A loop wrapper for GenerateNamespace
// splitted for unit test !
func GenerateNamespaces(context []*types.AuthJWTTupple) {
	for _, auth := range context {
		GenerateNamespace(auth)
	}
}

// GenerateRolebinding from tupple
// If exists, nothing is done, only creating !
func GenerateRoleBinding(context *types.AuthJWTTupple) {
	kconfig, err := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	api := clientSet.RbacV1()

	roleBindingName := fmt.Sprintf("%s-%s", context.Namespace, context.Role)
	_, errRB := api.RoleBindings(context.Namespace).Get(roleBindingName, metav1.GetOptions{})

	if errRB == nil {
		utils.Log.Info().Msgf("Rolebinding: %v already exists for namespace %v", roleBindingName, context.Namespace)
		return
	}

	utils.Log.Info().Msgf("Rolebinding %v doesn't exist for namespace %v and role %v", roleBindingName, context.Namespace, context.Role)
	newRoleBinding := v1.RoleBinding{
		RoleRef: v1.RoleRef{
			"rbac.authorization.k8s.io",
			"ClusterRole",
			"cluster-admin",
		},
		Subjects: []v1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Group",
				Name:     roleBindingName,
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: context.Namespace,
			Labels: map[string]string{
				"name":    roleBindingName,
				"creator": "kubi",
			},
		},
	}
	_, err = api.RoleBindings(context.Namespace).Create(&newRoleBinding)
	if err != nil {
		utils.Log.Error().Msg(err.Error())
	}

}

// GenerateRolebinding from tupple
// If exists, nothing is done, only creating !
func GenerateNamespace(context *types.AuthJWTTupple) {
	kconfig, err := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	_, errNs := api.Namespaces().Get(context.Namespace, metav1.GetOptions{})

	if errNs != nil {
		utils.Log.Info().Msgf("Creating namespace %v", context.Namespace)
		namespace := &corev1.Namespace{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Namespace",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: context.Namespace,
				Labels: map[string]string{
					"name":    context.Namespace,
					"type":    "customer",
					"creator": "kubi",
				},
			},
		}
		namespace, err = api.Namespaces().Create(namespace)
		if err != nil {
			utils.Log.Error().Err(err)
		}
	}

}
