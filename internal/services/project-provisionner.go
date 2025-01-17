package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ca-gip/kubi/internal/ldap"
	projectpkg "github.com/ca-gip/kubi/internal/project"
	"github.com/ca-gip/kubi/internal/utils"
	cagipv1 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	"github.com/ca-gip/kubi/pkg/generated/clientset/versioned"
	"github.com/ca-gip/kubi/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var ProjectCreation = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "kubi_project_creation",
	Help: "Number of project created",
}, []string{"status", "name"})

func RefreshProjectsFromLdap(ldapClient *ldap.LDAPClient, whitelistEnabled bool) {
	slog.Info("Generating resources from LDAP groups")

	for {
		slog.Info("new tick, now creating or updating projects from LDAP")
		clusterProjects, err := ldapClient.ListProjects()
		if err != nil {
			slog.Error("cannot get project list from ldap", "error", err)
		}
		kconfig, _ := rest.InClusterConfig()
		clientSet, _ := kubernetes.NewForConfig(kconfig)
		api := clientSet.CoreV1()
		blackWhiteList := types.BlackWhitelist{}

		blacklistCM, errRB := GetBlackWhitelistCM(api)
		if errRB != nil {
			slog.Error("Can't get configmap containing the blacklist or whitelist, retrying in a minute", "error", errRB)
			// instead of waiting a full 10 minute tick in case an api server is slow, just retry a minute later.
			time.Sleep(time.Minute)
			continue
		}

		blackWhiteList = projectpkg.MakeBlackWhitelist(blacklistCM.Data)

		createdproject, deletedprojects, ignoredProjects := projectpkg.FilterProjects(whitelistEnabled, clusterProjects, &blackWhiteList)
		for _, project := range ignoredProjects {
			slog.Error("Cannot find project in whitelist", "namespace", project.Namespace())
		}
		for _, project := range deletedprojects {
			slog.Info("deleting project in blacklist", "namespace", project.Namespace())
			deleteProject(project)
		}
		// now that the project is well categorized we know that a project cannot be at the same  time to be deleted and to be generated
		for _, project := range createdproject {
			slog.Info("creating or updating projec", "namespace", project.Namespace())
			generateProject(project)
		}
		time.Sleep(10 * time.Minute)
	}
}

func appendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

// generate a project config or update it if exists
func generateProject(projectInfos *types.Project) {
	// todo: cleanup this funvtion for testability...
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)

	existingProject, errProject := clientSet.CagipV1().Projects().Get(context.TODO(), projectInfos.Namespace(), metav1.GetOptions{})

	splits := strings.Split(projectInfos.Namespace(), "-")
	if len(splits) < 2 {
		slog.Info("Provisionner: The project is not splittable in two parts: <namespace>-<environment>.", "namespace", projectInfos.Namespace())
	}

	project := &cagipv1.Project{
		Spec: cagipv1.ProjectSpec{},
		Status: cagipv1.ProjectSpecStatus{
			Name: cagipv1.ProjectStatusCreated,
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
	case projectpkg.KubiEnvironmentDevelopment:
		project.Spec.Stages = []string{utils.KubiStageScratch, utils.KubiStageStaging, utils.KubiStageStable}
	case projectpkg.KubiEnvironmentIntegration:
		project.Spec.Stages = []string{utils.KubiStageStaging, utils.KubiStageStable}
	case projectpkg.KubiEnvironmentUAT:
		project.Spec.Stages = []string{utils.KubiStageStaging, utils.KubiStageStable}
	case projectpkg.KubiEnvironmentPreproduction:
		project.Spec.Stages = []string{utils.KubiStageStable}
	case projectpkg.KubiEnvironmentProduction:
		project.Spec.Stages = []string{utils.KubiStageStable}
	default:
		slog.Info("Provisionner: Can't map stage and environment for project", "namespace", projectInfos.Namespace())
	}

	project.Spec.SourceEntity = projectInfos.Source
	project.Spec.SourceDN = fmt.Sprintf("CN=%s,%s", projectInfos.Source, utils.Config.Ldap.GroupBase)
	if utils.Config.Tenant != utils.KubiTenantUndeterminable {
		project.Spec.Tenant = utils.Config.Tenant
	}

	if errProject != nil {
		slog.Info("Project does not exist and will be created", "namespace", projectInfos.Namespace())
		_, errorCreate := clientSet.CagipV1().Projects().Create(context.TODO(), project, metav1.CreateOptions{})
		if errorCreate != nil {
			slog.Error("failed to create project", "namespace", projectInfos.Namespace(), "error", errorCreate)
			ProjectCreation.WithLabelValues("error", projectInfos.Project).Inc()
		}
		ProjectCreation.WithLabelValues("created", projectInfos.Project).Inc()
		return
	} else {
		slog.Info("Project already exists, will be updated", "namespace", projectInfos.Namespace())
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
			existingProject.Spec.Stages = appendIfMissing(existingProject.Spec.Stages, stage)
		}
		existingProject.Spec.SourceEntity = projectInfos.Source
		existingProject.Spec.SourceDN = fmt.Sprintf("CN=%s,%s", projectInfos.Source, utils.Config.Ldap.GroupBase)
		_, errUpdate := clientSet.CagipV1().Projects().Update(context.TODO(), existingProject, metav1.UpdateOptions{})
		if errUpdate != nil {
			slog.Error("could not update project", "namespace", projectInfos.Namespace(), "error", errUpdate)
			ProjectCreation.WithLabelValues("error", projectInfos.Project).Inc()
			return
		}
		ProjectCreation.WithLabelValues("updated", projectInfos.Project).Inc()
		return
	}
}

// delete a project ( for blacklist purpose )
func deleteProject(projectInfos *types.Project) {
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)

	errDeletionProject := clientSet.CagipV1().Projects().Delete(context.TODO(), projectInfos.Namespace(), metav1.DeleteOptions{})

	if errDeletionProject != nil {
		slog.Error("Cannot delete project", "namespace", projectInfos.Namespace())
		return
	}

	slog.Info("Project deleted", "namespace", projectInfos.Namespace())
}
