package services

import (
	"errors"
	"fmt"
	"github.com/ca-gip/kubi/internal/authprovider"
	"github.com/ca-gip/kubi/internal/types"
	"github.com/ca-gip/kubi/internal/utils"
	v12 "github.com/ca-gip/kubi/pkg/apis/ca-gip/v1"
	"github.com/ca-gip/kubi/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	v1n "k8s.io/api/networking/v1"
	"k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"net/http"
	"strings"
	"time"
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
	GenerateProjects(auths)
	WatchNetPolConfig()
	WatchProjects()
	return nil
}

// A loop wrapper for GenerateRoleBinding
// splitted for unit test !
func GenerateRoleBindings(context []*types.NamespaceAndRole) {
	for _, auth := range context {
		GenerateRoleBinding(auth)
	}
}

// A loop wrapper for generateProject
// splitted for unit test !
func GenerateProjects(context []*types.NamespaceAndRole) {
	for _, auth := range context {
		generateProject(auth.Namespace)
	}
}

// generate a project config or update it if exists
func generateProject(projectName string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)
	existingProject, errProject := clientSet.CagipV1().Projects().Get(projectName, metav1.GetOptions{})

	splits := strings.Split(projectName, "-")
	if len(splits) < 2 {
		utils.Log.Warn().Msgf("Provisionner: The project %v could'nt be split in two part: <namespace>-<environment>.", projectName)
	}

	project := &v12.Project{
		Spec: v12.ProjectSpec{},
		Status: v12.ProjectSpecStatus{
			Name: "created",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: projectName,
			Labels: map[string]string{
				"creator": "kubi",
			},
		},
	}

	if utils.Config.Tenant != utils.KubiTenantUndeterminable {
		project.Spec.Tenant = utils.Config.Tenant
	}

	if strings.HasSuffix(projectName, utils.KubiEnvironmentDevelopment) {
		project.Spec.Project = strings.TrimSuffix(projectName, "-"+utils.KubiEnvironmentDevelopment)
		project.Spec.Environment = utils.KubiEnvironmentDevelopment
		project.Spec.Stages = append(project.Spec.Stages, utils.KubiStageScratch)
	} else if strings.HasSuffix(projectName, utils.KubiEnvironmentIntegration) {
		project.Spec.Project = strings.TrimSuffix(projectName, "-"+utils.KubiEnvironmentIntegration)
		project.Spec.Environment = utils.KubiEnvironmentIntegration
		project.Spec.Stages = append(project.Spec.Stages, utils.KubiStageStaging)
	} else if strings.HasSuffix(projectName, utils.KubiEnvironmentProduction) {
		project.Spec.Project = strings.TrimSuffix(projectName, "-"+utils.KubiEnvironmentProduction)
		project.Spec.Environment = utils.KubiEnvironmentProduction
		project.Spec.Stages = append(project.Spec.Stages, utils.KubiStageStable)
	} else {
		utils.Log.Warn().Msgf("Provisionner: Can't map stage and environment for project %v.", projectName)
		project.Spec.Project = projectName
	}

	if utils.Config.Tenant != utils.KubiTenantUndeterminable {
		project.Spec.Tenant = utils.Config.Tenant
	}

	if errProject != nil {
		utils.Log.Info().Msgf("Project: %v doesn't exist, will be created", projectName)
		_, errorCreate := clientSet.CagipV1().Projects().Create(project)
		if errorCreate != nil {
			utils.Log.Error().Msg(errorCreate.Error())
		}
		return
	} else {
		utils.Log.Info().Msgf("Project: %v already exists, will be updated", projectName)
		existingProject.Spec.Project = project.Spec.Project
		if len(project.Spec.Environment) > 0 {
			existingProject.Spec.Environment = project.Spec.Environment
		}
		existingProject.Spec.Tenant = project.Spec.Tenant
		for _, stage := range project.Spec.Stages {
			existingProject.Spec.Stages = utils.AppendIfMissing(existingProject.Spec.Stages, stage)
		}
		_, errUpdate := clientSet.CagipV1().Projects().Update(existingProject)
		if errUpdate != nil {
			utils.Log.Error().Msg(errUpdate.Error())
		}
	}
}

// GenerateRolebinding from tupple
// If exists, nothing is done, only creating !
func GenerateRoleBinding(context *types.NamespaceAndRole) {
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
func generateNamespace(namespace string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, err := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	_, errNs := api.Namespaces().Get(namespace, metav1.GetOptions{})

	if errNs != nil {
		utils.Log.Info().Msgf("Creating namespace %v", namespace)
		namespace := &corev1.Namespace{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Namespace",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
				Labels: map[string]string{
					"name":    namespace,
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

// Watch NetworkPolicyConfig, which is a config object for namespace network bubble
// This CRD allow user to deploy global configuration for network configuration
// for update, the default network config is updated
// for deletion, it is automatically recreated
// for create, just create it
func WatchProjects() cache.Store {
	kconfig, _ := rest.InClusterConfig()

	v3, _ := versioned.NewForConfig(kconfig)

	watchlist := cache.NewListWatchFromClient(v3.CagipV1().RESTClient(), "projects", metav1.NamespaceAll, fields.Everything())
	resyncPeriod := 30 * time.Minute

	store, controller := cache.NewInformer(watchlist, &v12.Project{}, resyncPeriod, cache.ResourceEventHandlerFuncs{
		AddFunc:    projectCreated,
		DeleteFunc: projectDelete,
		UpdateFunc: projectUpdate,
	})

	go controller.Run(wait.NeverStop)

	return store
}

func projectUpdate(old interface{}, new interface{}) {
	newProject := new.(*v12.Project)
	utils.Log.Info().Msgf("Operator: the project %v has been updated, updating associated resources: namespace, networkpolicies.", newProject.Name)
	generateNamespace(newProject.Name)
	generateNetworkPolicy(newProject.Name, nil)

	// TODO: Refactor with a non static list of roles
	GenerateRoleBinding(&types.NamespaceAndRole{Namespace: newProject.Name, Role: "admin"})
	GenerateRoleBinding(&types.NamespaceAndRole{Namespace: newProject.Name, Role: "developper"})
	GenerateRoleBinding(&types.NamespaceAndRole{Namespace: newProject.Name, Role: "viewer"})

}

func projectCreated(obj interface{}) {
	project := obj.(*v12.Project)
	utils.Log.Info().Msgf("Operator: the project %v has been created, generating associated resources: namespace, networkpolicies.", project.Name)
	generateNamespace(project.Name)
	generateNetworkPolicy(project.Name, nil)

	// TODO: Refactor with a non static list of roles
	GenerateRoleBinding(&types.NamespaceAndRole{Namespace: project.Name, Role: "admin"})
	GenerateRoleBinding(&types.NamespaceAndRole{Namespace: project.Name, Role: "developper"})
	GenerateRoleBinding(&types.NamespaceAndRole{Namespace: project.Name, Role: "viewer"})
}

func projectDelete(obj interface{}) {
	project := obj.(*v12.Project)
	utils.Log.Info().Msgf("Operator: the project %v has been deleted, Kubi won't delete anything, please delete the namespace %v manualy", project.Name, project.Name)
}

// Watch NetworkPolicyConfig, which is a config object for namespace network bubble
// This CRD allow user to deploy global configuration for network configuration
// for update, the default network config is updated
// for deletion, it is automatically recreated
// for create, just create it
func WatchNetPolConfig() cache.Store {
	kconfig, _ := rest.InClusterConfig()

	v3, _ := versioned.NewForConfig(kconfig)

	watchlist := cache.NewListWatchFromClient(v3.CagipV1().RESTClient(), "networkpolicyconfigs", metav1.NamespaceAll, fields.Everything())
	resyncPeriod := 30 * time.Minute

	store, controller := cache.NewInformer(watchlist, &v12.NetworkPolicyConfig{}, resyncPeriod, cache.ResourceEventHandlerFuncs{
		AddFunc:    networkPolicyConfigCreated,
		DeleteFunc: networkPolicyConfigDelete,
		UpdateFunc: networkPolicyConfigUpdate,
	})

	go controller.Run(wait.NeverStop)

	return store
}

func networkPolicyConfigUpdate(old interface{}, new interface{}) {
	netpolconfig := new.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has changed, refreshing associated resources: networkpolicies, for all kubi's namespaces.", netpolconfig.Name)

	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)
	projects, err := clientSet.CagipV1().Projects().List(metav1.ListOptions{})

	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return
	}

	for _, project := range projects.Items {
		utils.Log.Info().Msgf("Operator: refresh network policy for %v", project.Name)
		generateNetworkPolicy(project.Name, netpolconfig)
	}

}

func networkPolicyConfigCreated(obj interface{}) {
	netpolconfig := obj.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has been created, refreshing associated resources: networkpolicies, for all kubi's namespaces.", netpolconfig.Name)

	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)
	projects, err := clientSet.CagipV1().Projects().List(metav1.ListOptions{})

	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return
	}

	for _, project := range projects.Items {
		utils.Log.Info().Msgf("Operator: refresh network policy for %v", project.Name)
		generateNetworkPolicy(project.Name, netpolconfig)
	}
}

func networkPolicyConfigDelete(obj interface{}) {
	netpolconfig := obj.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has been deleted, please delete networkpolicies for all kubi's namespaces. Be careful !", netpolconfig.Name)
}

// Generate a NetworkPolicy based on NetworkPolicyConfig
// If exists, the existing netpol is updated else it is created
func generateNetworkPolicy(namespace string, networkPolicyConfig *v12.NetworkPolicyConfig) {

	kconfig, _ := rest.InClusterConfig()

	if networkPolicyConfig == nil {
		extendedClientSet, _ := versioned.NewForConfig(kconfig)
		existingNetworkPolicyConfig, err := extendedClientSet.CagipV1().NetworkPolicyConfigs().Get(utils.KubiDefaultNetworkPolicyName, metav1.GetOptions{})
		networkPolicyConfig = existingNetworkPolicyConfig
		if err != nil {
			utils.Log.Info().Msgf("Operator: No default network policy config \"%v\" found, cannot create/update namespace security !, Error: %v", utils.KubiDefaultNetworkPolicyName, err.Error())
		}

	}

	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.NetworkingV1()
	_, errNetpol := api.NetworkPolicies(namespace).Get(utils.KubiDefaultNetworkPolicyName, metav1.GetOptions{})

	UDP := corev1.ProtocolUDP
	TCP := corev1.ProtocolTCP

	ingressNamespaces := map[string]string{}
	for _, namespace := range networkPolicyConfig.Spec.Ingress.Namespaces {
		ingressNamespaces["name"] = namespace
	}

	netpolPorts := []v1n.NetworkPolicyPort{}

	if len(networkPolicyConfig.Spec.Egress.Ports) > 0 {
		for _, port := range networkPolicyConfig.Spec.Egress.Ports {
			netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port)}, Protocol: &UDP})
			netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port)}, Protocol: &TCP})
		}
	}
	netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: 53}, Protocol: &UDP})

	policyPeers := []v1n.NetworkPolicyPeer{
		{PodSelector: &metav1.LabelSelector{MatchLabels: nil}},
		{NamespaceSelector: &metav1.LabelSelector{MatchLabels: nil}},
	}

	for _, cidr := range networkPolicyConfig.Spec.Egress.Cidrs {
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
