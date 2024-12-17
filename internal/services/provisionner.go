package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	ldap "github.com/ca-gip/kubi/internal/authprovider"
	"github.com/ca-gip/kubi/internal/utils"
	v12 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	"github.com/ca-gip/kubi/pkg/generated/clientset/versioned"
	"github.com/ca-gip/kubi/pkg/types"
	corev1 "k8s.io/api/core/v1"
	v1n "k8s.io/api/networking/v1"
	v1 "k8s.io/api/rbac/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	kubernetes "k8s.io/client-go/kubernetes"
	v13 "k8s.io/client-go/kubernetes/typed/core/v1"
	v14 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	podSecurity "k8s.io/pod-security-admission/api"
)

// Handler to regenerate all resources created by kubi
func RefreshK8SResources() {
	err := GenerateResources()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
	}
}

// Generate Namespaces and Rolebinding from Ldap groups
func GenerateResources() error {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()
	blackWhiteList := types.BlackWhitelist{}

	groups, err := ldap.GetAllGroups()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return err
	}
	if len(groups) == 0 {
		return fmt.Errorf("no ldap groups found")
	}
	auths := GetUserNamespaces(groups)

	blacklistCM, errRB := GetBlackWhitelistCM(api)
	if errRB != nil {
		utils.Log.Info().Msg("Can't get Black&Whitelist")
		return err
	} else {
		blackWhiteList = MakeBlackWhitelist(blacklistCM.Data)
	}

	createdproject, deletedprojects, ignoredProjects := GenerateProjects(auths, &blackWhiteList)
	for _, project := range ignoredProjects {
		utils.Log.Error().Msgf("Cannot find project %s in whitelist", project.Namespace())
	}
	for _, project := range deletedprojects {
		utils.Log.Info().Msgf("delete project %s in blacklist", project.Namespace())
		deleteProject(project)
	}
	// now that the project is well categorized we know that a project cannot be at the same  time to be deleted and to be generated
	for _, project := range createdproject {
		utils.Log.Info().Msgf("Project %s is whitelisted", project.Namespace())
		generateProject(project)
	}
	return nil
}

// A loop wrapper for generateProject
// splitted for unit test !
func GenerateProjects(context []*types.Project, blackWhiteList *types.BlackWhitelist) ([]*types.Project, []*types.Project, []*types.Project) {

	var createdProjects, deletedProjects, ignoredProjects []*types.Project
	for _, auth := range context {
		isBlacklisted := slices.Contains(blackWhiteList.Blacklist, auth.Namespace())
		isWhitelisted := slices.Contains(blackWhiteList.Whitelist, auth.Namespace())

		switch {
		//we treat blacklisted projects as a priority, project will be deleted
		case blackWhiteList.Blacklist[0] != "" && isBlacklisted:
			deletedProjects = append(deletedProjects, auth)
			continue
		// If whitelist is enabled, do not create project unless it's explictly mentioned
		case utils.Config.Whitelist && isWhitelisted:
			createdProjects = append(createdProjects, auth)
		//project will be ignored if whitelist  is enabled and project not present on whitelisted projects
		case utils.Config.Whitelist && !isWhitelisted:
			ignoredProjects = append(ignoredProjects, auth)
		//project will be created if whitelist is disabled and no projects in blacklist
		default:
			createdProjects = append(createdProjects, auth)
		}
	}

	return createdProjects, deletedProjects, ignoredProjects
}

// generate a project config or update it if exists
func generateProject(projectInfos *types.Project) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)

	existingProject, errProject := clientSet.CagipV1().Projects().Get(context.TODO(), projectInfos.Namespace(), metav1.GetOptions{})

	splits := strings.Split(projectInfos.Namespace(), "-")
	if len(splits) < 2 {
		utils.Log.Warn().Msgf("Provisionner: The project %v could'nt be split in two part: <namespace>-<environment>.", projectInfos.Namespace())
	}

	project := &v12.Project{
		Spec: v12.ProjectSpec{},
		Status: v12.ProjectSpecStatus{
			Name: v12.ProjectStatusCreated,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: projectInfos.Namespace(),
			Labels: map[string]string{
				"creator": "kubi",
			},
		},
	}

	if utils.Config.Tenant != utils.KubiTenantUndeterminable {
		project.Spec.Tenant = utils.Config.Tenant
	}

	project.Spec.Project = projectInfos.Project
	project.Spec.Environment = projectInfos.Environment

	switch projectInfos.Environment {
	case utils.KubiEnvironmentDevelopment:
		project.Spec.Stages = []string{utils.KubiStageScratch, utils.KubiStageStaging, utils.KubiStageStable}
	case utils.KubiEnvironmentIntegration:
		project.Spec.Stages = []string{utils.KubiStageStaging, utils.KubiStageStable}
	case utils.KubiEnvironmentUAT:
		project.Spec.Stages = []string{utils.KubiStageStaging, utils.KubiStageStable}
	case utils.KubiEnvironmentPreproduction:
		project.Spec.Stages = []string{utils.KubiStageStable}
	case utils.KubiEnvironmentProduction:
		project.Spec.Stages = []string{utils.KubiStageStable}
	default:
		utils.Log.Warn().Msgf("Provisionner: Can't map stage and environment for project %v.", projectInfos.Namespace())
	}

	project.Spec.SourceEntity = projectInfos.Source
	project.Spec.SourceDN = fmt.Sprintf("CN=%s,%s", projectInfos.Source, utils.Config.Ldap.GroupBase)
	if utils.Config.Tenant != utils.KubiTenantUndeterminable {
		project.Spec.Tenant = utils.Config.Tenant
	}

	if errProject != nil {
		utils.Log.Info().Msgf("Project: %v doesn't exist, will be created", projectInfos.Namespace())
		_, errorCreate := clientSet.CagipV1().Projects().Create(context.TODO(), project, metav1.CreateOptions{})
		if errorCreate != nil {
			utils.Log.Error().Msg(errorCreate.Error())
			utils.ProjectCreation.WithLabelValues("error", projectInfos.Project).Inc()
		} else {
			utils.ProjectCreation.WithLabelValues("created", projectInfos.Project).Inc()
		}
		return
	} else {
		utils.Log.Info().Msgf("Project: %v already exists, will be updated", projectInfos.Namespace())
		existingProject.Spec.Project = project.Spec.Project
		if len(project.Spec.Contact) > 0 {
			existingProject.Spec.Contact = project.Spec.Contact
		}
		if len(project.Spec.Environment) > 0 {
			existingProject.Spec.Environment = project.Spec.Environment
		}
		if len(existingProject.Spec.Tenant) == 0 {
			existingProject.Spec.Tenant = project.Spec.Tenant
		}
		for _, stage := range project.Spec.Stages {
			existingProject.Spec.Stages = utils.AppendIfMissing(existingProject.Spec.Stages, stage)
		}
		existingProject.Spec.SourceEntity = projectInfos.Source
		existingProject.Spec.SourceDN = fmt.Sprintf("CN=%s,%s", projectInfos.Source, utils.Config.Ldap.GroupBase)
		_, errUpdate := clientSet.CagipV1().Projects().Update(context.TODO(), existingProject, metav1.UpdateOptions{})
		if errUpdate != nil {
			utils.Log.Error().Msg(errUpdate.Error())
			utils.ProjectCreation.WithLabelValues("error", projectInfos.Project).Inc()
		} else {
			utils.ProjectCreation.WithLabelValues("updated", projectInfos.Project).Inc()
		}
	}
}

// delete a project ( for blacklist purpose )
func deleteProject(projectInfos *types.Project) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)

	errDeletionProject := clientSet.CagipV1().Projects().Delete(context.TODO(), projectInfos.Namespace(), metav1.DeleteOptions{})

	if errDeletionProject != nil {
		utils.Log.Info().Msgf("Cannot delete project: %v", projectInfos.Namespace())
		return
	}

	utils.Log.Info().Msgf("Project: %v deleted", projectInfos.Namespace())
}

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

// Generate
func GenerateAppServiceAccount(namespace string) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := kubernetes.NewForConfig(kconfig)
	api := clientSet.CoreV1()

	_, errRB := api.ServiceAccounts(namespace).Get(context.TODO(), utils.KubiServiceAccountAppName, metav1.GetOptions{})

	newServiceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.KubiServiceAccountAppName,
			Namespace: namespace,
			Labels: map[string]string{
				"name":    utils.KubiServiceAccountAppName,
				"creator": "kubi",
				"version": "v3",
			},
		},
	}

	if errRB != nil {
		_, err := api.ServiceAccounts(namespace).Create(context.TODO(), &newServiceAccount, metav1.CreateOptions{})
		if err != nil {
			utils.Log.Error().Msg(err.Error())
			utils.ServiceAccountCreation.WithLabelValues("error", namespace, utils.KubiServiceAccountAppName).Inc()
			return
		}
		utils.Log.Info().Msgf("Service Account %v has been created for namespace %v", utils.KubiServiceAccountAppName, namespace)
		utils.ServiceAccountCreation.WithLabelValues("created", namespace, utils.KubiServiceAccountAppName).Inc()
		return
	}
	utils.ServiceAccountCreation.WithLabelValues("ok", namespace, utils.KubiServiceAccountAppName).Inc()
}

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

	return utils.Union(defaultLabels, utils.Config.CustomLabels)
}

func GetPodSecurityStandardName(namespace string) string {
	if utils.IsInPrivilegedNsList(namespace) {
		utils.Log.Warn().Msgf("Namespace %v is labeled as privileged", namespace)
		return string(podSecurity.LevelPrivileged)
	}
	return string(utils.Config.PodSecurityAdmissionEnforcement)
}

// Watch NetworkPolicyConfig, which is a config object for namespace network bubble
// This CRD allow user to deploy global configuration for network configuration
// for update, the default network config is updated
// for deletion, it is automatically recreated
// for create, just create it
func WatchProjects() cache.Store {
	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return nil
	}

	v3, err := versioned.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return nil
	}

	watchlist := cache.NewFilteredListWatchFromClient(v3.CagipV1().RESTClient(), "projects", metav1.NamespaceAll, utils.DefaultWatchOptionModifier)
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

	err := generateNamespace(newProject)
	if err != nil {
		utils.Log.Warn().Msgf("Unexpected error %s", err)
		return
	}

	if utils.Config.NetworkPolicy {
		generateNetworkPolicy(newProject.Name, nil)
	}
	// TODO: Refactor with a non static list of roles
	GenerateUserRoleBinding(newProject.Name, "admin")
	GenerateAppServiceAccount(newProject.Name)
	GenerateAppRoleBinding(newProject.Name)
	if !strings.EqualFold(utils.Config.DefaultPermission, "") {
		GenerateDefaultRoleBinding(newProject.Name)
	}

}

func projectCreated(obj interface{}) {
	project := obj.(*v12.Project)
	utils.Log.Info().Msgf("Operator: the project %v has been created, generating associated resources: namespace, networkpolicies.", project.Name)

	err := generateNamespace(project)
	if err != nil {
		utils.Log.Warn().Msgf("Unexpected error %s", err)
		return
	}

	if utils.Config.NetworkPolicy {
		generateNetworkPolicy(project.Name, nil)
	}

	// TODO: Refactor with a non static list of roles
	GenerateUserRoleBinding(project.Name, "admin")
	GenerateAppServiceAccount(project.Name)
	GenerateAppRoleBinding(project.Name)
	if !strings.EqualFold(utils.Config.DefaultPermission, "") {
		GenerateDefaultRoleBinding(project.Name)
	}

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
	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return nil
	}

	v3, err := versioned.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return nil
	}

	watchlist := cache.NewFilteredListWatchFromClient(v3.CagipV1().RESTClient(), "networkpolicyconfigs", metav1.NamespaceAll, utils.DefaultWatchOptionModifier)

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

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return
	}

	clientSet, err := versioned.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return
	}

	projects, err := clientSet.CagipV1().Projects().List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return
	}

	for _, project := range projects.Items {
		utils.Log.Info().Msgf("Operator: refresh network policy for %v", project.Name)
		if utils.Config.NetworkPolicy {
			generateNetworkPolicy(project.Name, netpolconfig)
		}
	}

}

func networkPolicyConfigCreated(obj interface{}) {
	netpolconfig := obj.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has been created, refreshing associated resources: networkpolicies, for all kubi's namespaces.", netpolconfig.Name)

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return
	}

	clientSet, err := versioned.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return
	}

	projects, err := clientSet.CagipV1().Projects().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return
	}

	for _, project := range projects.Items {
		utils.Log.Info().Msgf("Operator: refresh network policy for %v", project.Name)
		if utils.Config.NetworkPolicy {
			generateNetworkPolicy(project.Name, netpolconfig)
		}
	}
}

func networkPolicyConfigDelete(obj interface{}) {
	netpolconfig := obj.(*v12.NetworkPolicyConfig)
	utils.Log.Info().Msgf("Operator: the network config %v has been deleted, please delete networkpolicies for all kubi's namespaces. Be careful !", netpolconfig.Name)
}

// Generate a NetworkPolicy based on NetworkPolicyConfig
// If exists, the existing netpol is updated else it is created
func generateNetworkPolicy(namespace string, networkPolicyConfig *v12.NetworkPolicyConfig) {

	kconfig, err := rest.InClusterConfig()
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating in cluster config %v", err.Error())) // TODO: Cleanup those calls to be less wrapped and simpler.
		return
	}

	if networkPolicyConfig == nil {
		extendedClientSet, err := versioned.NewForConfig(kconfig)
		if err != nil {
			utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes extended clientset, %v", err.Error()))
			return
		}
		existingNetworkPolicyConfig, err := extendedClientSet.CagipV1().NetworkPolicyConfigs().Get(context.TODO(), utils.KubiDefaultNetworkPolicyName, metav1.GetOptions{})
		if err != nil {
			utils.Log.Info().Msgf("Operator: No default network policy config \"%v\" found, cannot create/update namespace security !, Error: %v", utils.KubiDefaultNetworkPolicyName, err.Error())
			utils.NetworkPolicyCreation.WithLabelValues("error", namespace, utils.KubiDefaultNetworkPolicyName).Inc()
		}
		networkPolicyConfig = existingNetworkPolicyConfig
	}

	clientSet, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("error creating kubernetes clientset, %v", err.Error()))
		return
	}

	api := clientSet.NetworkingV1()
	_, errNetpol := api.NetworkPolicies(namespace).Get(context.TODO(), utils.KubiDefaultNetworkPolicyName, metav1.GetOptions{})

	UDP := corev1.ProtocolUDP
	TCP := corev1.ProtocolTCP

	var ingressRules []v1n.NetworkPolicyPeer

	// Add default intra namespace communication
	ingressRules = append(ingressRules, v1n.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{MatchLabels: nil},
	})

	// Add default whitelisted namespace ingress rules
	for _, namespace := range networkPolicyConfig.Spec.Ingress.Namespaces {
		ingressRules = append(ingressRules, v1n.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": namespace}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: nil},
		})
	}

	var netpolPorts []v1n.NetworkPolicyPort

	if len(networkPolicyConfig.Spec.Egress.Ports) > 0 {
		for _, port := range networkPolicyConfig.Spec.Egress.Ports {
			netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port)}, Protocol: &UDP})
			netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: int32(port)}, Protocol: &TCP})
		}
	}
	netpolPorts = append(netpolPorts, v1n.NetworkPolicyPort{Port: &intstr.IntOrString{IntVal: 53}, Protocol: &UDP})

	policyPeers := []v1n.NetworkPolicyPeer{
		{PodSelector: &metav1.LabelSelector{MatchLabels: nil}},
		{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "kube-system"}},
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"component": "kube-apiserver",
					"tier":      "control-plane",
				},
			},
		},
	}

	// Add default whitelisted namespace egress rules
	for _, namespace := range networkPolicyConfig.Spec.Egress.Namespaces {
		policyPeers = append(policyPeers, v1n.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": namespace}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: nil},
		})
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
					From: ingressRules,
				},
			},
			Egress: []v1n.NetworkPolicyEgressRule{
				{
					Ports: netpolPorts,
				},
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
		_, err := api.NetworkPolicies(namespace).Create(context.TODO(), networkpolicy, metav1.CreateOptions{})
		if err != nil {
			utils.NetworkPolicyCreation.WithLabelValues("error", namespace, utils.KubiDefaultNetworkPolicyName).Inc()
		} else {
			utils.NetworkPolicyCreation.WithLabelValues("created", namespace, utils.KubiDefaultNetworkPolicyName).Inc()
		}
		utils.Check(err)
		return
	} else {
		_, err := api.NetworkPolicies(namespace).Update(context.TODO(), networkpolicy, metav1.UpdateOptions{})
		if err != nil {
			utils.NetworkPolicyCreation.WithLabelValues("error", namespace, utils.KubiDefaultNetworkPolicyName).Inc()
		} else {
			utils.NetworkPolicyCreation.WithLabelValues("updated", namespace, utils.KubiDefaultNetworkPolicyName).Inc()
		}
		utils.Check(err)
		return
	}
}
