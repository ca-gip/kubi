package services

import (
	"errors"
	"fmt"
	"github.com/ca-gip/kubi/authprovider"
	"github.com/ca-gip/kubi/types"
	"github.com/ca-gip/kubi/utils"
	corev1 "k8s.io/api/core/v1"
	v1n "k8s.io/api/networking/v1"
	"k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"strconv"
)

// Handler to regenerate all resources created by kubi
func RefreshK8SResources(w http.ResponseWriter, _ *http.Request) {

	w.WriteHeader(http.StatusAccepted)
	GenerateAdminClusterRoleBinding()
	err := GenerateResources()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
	}
}

// Generate Namespaces and Rolebinding from Ldap groups
func GenerateResources() error {
	groups, err := ldap.GetAllGroups()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return err
	}
	if len(groups) == 0 {
		return errors.New("LDAP, no ldap groups found!")
	}
	auths := GetUserNamespaces(groups)
	GenerateNamespaces(auths)
	GenerateRoleBindings(auths)
	GenerateNetworkPolicies(auths)
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

// A loop wrapper for GenerateNetworkPolicy
// splitted for unit test !
func GenerateNetworkPolicies(context []*types.AuthJWTTupple) {
	if utils.Config.NetworkPolicyConfig == nil {
		utils.Log.Info().Msg("Network policy generation is not enabled")
		return
	}
	utils.Log.Info().Msg("Network policy generation is enabled")
	for _, auth := range context {
		utils.Log.Info().Msgf("Generate NetworkPolicy for %v", auth.Namespace)
		GenerateNetworkPolicy(auth.Namespace)
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
func GenerateAdminClusterRoleBinding() {
	kconfig, err := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	api := clientSet.RbacV1()

	_, errRB := api.ClusterRoleBindings().Get(utils.KubiClusterRoleBindingName, metav1.GetOptions{})

	if errRB == nil {
		utils.Log.Info().Msgf("ClusterRolebinding: %v already exists, nothing to do.", utils.KubiClusterRoleBindingName)
		return
	}

	utils.Log.Info().Msgf("ClusterRolebinding %v doesn't exist ", utils.KubiClusterRoleBindingName)

	clusterRoleBinding := v1.ClusterRoleBinding{
		RoleRef: v1.RoleRef{
			"rbac.authorization.k8s.io",
			"ClusterRole",
			"cluster-admin",
		},
		Subjects: []v1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Group",
				Name:     utils.KubiClusterRoleBindingName,
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: utils.KubiClusterRoleBindingName,
			Labels: map[string]string{
				"name":    utils.KubiClusterRoleBindingName,
				"creator": "kubi",
			},
		},
	}
	_, err = api.ClusterRoleBindings().Create(&clusterRoleBinding)
	if err != nil {
		utils.Log.Error().Msg(err.Error())
	}

}

// GenerateRolebinding from tupple
// If exists, nothing is done, only creating !
func GenerateNamespace(context *types.AuthJWTTupple) {
	kconfig, _ := rest.InClusterConfig()
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

// Generate a NetworkPolicy based on NetworkPolicyConfig
// If exists, the existing netpol is updates else it is created
func GenerateNetworkPolicy(namespace string) {
	kconfig, _ := rest.InClusterConfig()

	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.NetworkingV1()
	_, errNetpol := api.NetworkPolicies(namespace).Get(utils.KubiDefaultNetworkPolicyName, metav1.GetOptions{})

	UDP := corev1.ProtocolUDP
	TCP := corev1.ProtocolTCP

	ingressNamespaces := map[string]string{}
	for _, namespace := range utils.Config.NetworkPolicyConfig.AllowedNamespaceLabels {
		ingressNamespaces["name"] = namespace
	}

	netpolPorts := []v1n.NetworkPolicyPort{}
	utils.Log.Info().Msgf("Adding port %v to network policy  ns: %s, policy %s ", utils.Config.NetworkPolicyConfig.AllowedPorts, namespace, utils.KubiDefaultNetworkPolicyName)

	if len(utils.Config.NetworkPolicyConfig.AllowedPorts) > 0 {
		for _, port := range utils.Config.NetworkPolicyConfig.AllowedPorts {
			port32, err := strconv.Atoi(port)
			if err != nil {
				utils.Log.Error().Msgf("The following port %s is invalid, ignoring !", port)
			} else {
				netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port32)}, Protocol: &UDP})
				netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port32)}, Protocol: &TCP})
			}
		}
	}
	netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: 53}, Protocol: &UDP})

	policyPeers := []v1n.NetworkPolicyPeer{
		{PodSelector: &metav1.LabelSelector{MatchLabels: nil}},
		{NamespaceSelector: &metav1.LabelSelector{MatchLabels: nil}},
	}

	for _, cidr := range utils.Config.NetworkPolicyConfig.AllowedCidrs {
		utils.Log.Info().Msgf("Adding cidr block %v to network policy  ns: %s, policy %s ", utils.Config.NetworkPolicyConfig.AllowedCidrs, namespace, utils.KubiDefaultNetworkPolicyName)
		policyPeers = append(policyPeers, v1n.NetworkPolicyPeer{IPBlock: &v1n.IPBlock{CIDR: cidr}})
	}

	networkpolicy := &v1n.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.KubiDefaultNetworkPolicyName,
			Namespace: namespace,
		},
		Spec: v1n.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: nil,
			},
			Ingress: []v1n.NetworkPolicyIngressRule{
				{
					From: []v1n.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: nil}},
						{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: ingressNamespaces},
							PodSelector:       &metav1.LabelSelector{MatchLabels: nil}},
					},
				},
			},
			Egress: []v1n.NetworkPolicyEgressRule{
				{Ports: netpolPorts},
				{
					To: policyPeers,
				},
			},
			PolicyTypes: []v1n.PolicyType{
				v1n.PolicyTypeIngress, v1n.PolicyTypeEgress,
			},
		},
	}
	if errNetpol != nil {
		_, err := api.NetworkPolicies(namespace).Create(networkpolicy)
		utils.Check(err)
		return
	} else {
		_, err := api.NetworkPolicies(namespace).Update(networkpolicy)
		utils.Check(err)
		return
	}
}
