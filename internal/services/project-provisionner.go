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
)

func RefreshProjectsFromLdap(ldapClient *ldap.LDAPClient, whitelistEnabled bool) {
	slog.Info("Generating resources from LDAP groups")

	timerKubiRefresh := time.NewTicker(10 * time.Minute)

	for t := range timerKubiRefresh.C {

		utils.Log.Info().Msgf("new tick, now creating or updating projects from LDAP %s", t.String())
		clusterProjects, err := ldapClient.ListProjects()
		if err != nil {
			utils.Log.Error().Msgf("cannot get project list from ldap: %v", err)
		}
		kconfig, _ := rest.InClusterConfig()
		clientSet, _ := kubernetes.NewForConfig(kconfig)
		api := clientSet.CoreV1()
		blackWhiteList := types.BlackWhitelist{}

		blacklistCM, errRB := GetBlackWhitelistCM(api)
		if errRB != nil {
			utils.Log.Info().Msg("Can't get Black&Whitelist")
		} else {
			blackWhiteList = projectpkg.MakeBlackWhitelist(blacklistCM.Data)
		}

		createdproject, deletedprojects, ignoredProjects := projectpkg.FilterProjects(whitelistEnabled, clusterProjects, &blackWhiteList)
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
	kconfig, _ := rest.InClusterConfig()
	clientSet, _ := versioned.NewForConfig(kconfig)

	existingProject, errProject := clientSet.CagipV1().Projects().Get(context.TODO(), projectInfos.Namespace(), metav1.GetOptions{})

	splits := strings.Split(projectInfos.Namespace(), "-")
	if len(splits) < 2 {
		utils.Log.Warn().Msgf("Provisionner: The project %v could'nt be split in two part: <namespace>-<environment>.", projectInfos.Namespace())
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
			existingProject.Spec.Stages = appendIfMissing(existingProject.Spec.Stages, stage)
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
