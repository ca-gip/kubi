package services

import (
	"encoding/json"
	"testing"
	"github.com/ca-gip/kubi/internal/utils"
	v12 "github.com/ca-gip/kubi/pkg/apis/cagip/v1"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBlackWhiteList(t *testing.T) {

	fakeProjectJson := []byte(`{
		"apiVersion": "cagip.github.com/v1",
		"kind": "Project",
		"metadata": {
			"labels": {
				"creator": "kubi"
			},
			"name": "native-development",
		},
		"spec": {
			"environment": "development",
			"project": "native",
			"sourceDN": "CN=DL_KUB_CAGIP-DEVOPS-HP_NATIVE-DEVELOPMENT_ADMIN,OU=DEVOPS-HORS-PROD,OU=CAGIP,OU=PAAS_CONTAINER,OU=Applications,OU=Groupes,O=CA",
			"sourceEntity": "DL_KUB_CAGIP-DEVOPS-HP_NATIVE-DEVELOPMENT_ADMIN",
			"stages": [
				"scratch",
				"staging",
				"stable"
			],
			"tenant": "cagip"
		}
	}`)

	fakeProject := &v12.Project{}

	json.Unmarshal(fakeProjectJson, fakeProject)

	t.Run("with_nil_object", func(t *testing.T) {

		result := MakeBlackWhitelist(nil)
		assert.Equal(t, []string([]string{""}), result.Blacklist)
		assert.Equal(t, []string([]string{""}), result.Whitelist)
	})

	t.Run("with_empty_map", func(t *testing.T) {
		blackWhitelistData := map[string]string{}

		result := MakeBlackWhitelist(blackWhitelistData)
		assert.Equal(t, []string([]string{""}), result.Blacklist)
		assert.Equal(t, []string([]string{""}), result.Whitelist)
	})

	t.Run("with_non_sense_data", func(t *testing.T) {
		blackWhitelistData := map[string]string{
			"blacldzada":    "dzadzdaz",
			"dzadz$Ùdzadza": "fefezfez, 6z556/*/R/ÉR*/",
		}

		result := MakeBlackWhitelist(blackWhitelistData)
		assert.Equal(t, []string([]string{""}), result.Blacklist)
		assert.Equal(t, []string([]string{""}), result.Whitelist)
	})

	t.Run("with_real_data", func(t *testing.T) {
		blackWhitelistData := map[string]string{
			"blacklist": "native-developpement, native-integration",
			"whitelist": "",
		}

		result := MakeBlackWhitelist(blackWhitelistData)
		assert.Equal(t, []string([]string{"native-developpement", " native-integration"}), result.Blacklist)
		assert.Equal(t, []string([]string{""}), result.Whitelist)
	})

}

func TestGenerateProjects(t *testing.T) {

	fakeProject := []*types.Project{
		{
			Project:     "native",
			Environment: "development",
		},
		{
			Project:     "native",
			Environment: "integration",
		},
		{
			Project:     "native",
			Environment: "production",
		},
	}



	//WHITELIST
	t.Run("blacklisted projects are deleted and no whithelisted projects are ignored", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "",
		}
		expectedCreate := []*types.Project{
		}
		expectedDelete := []*types.Project{
			{
				Project:     "native",
				Environment: "development",
			},
			{
				Project:     "native",
				Environment: "integration",
			},
		} 
		expectedIgnore := []*types.Project{
			{
				Project:     "native",
				Environment: "production",
			},
		}

		blackWhitelist := MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: true}
		gotCreated,gotDeleted,gotIgnored := GenerateProjects(fakeProject, &blackWhitelist)
		assert.ElementsMatch(t,gotCreated,expectedCreate, "the expected create projects match created list ")
		assert.ElementsMatch(t,gotDeleted,expectedDelete, "the expected delete projects match deleted list ")
		assert.ElementsMatch(t,gotIgnored,expectedIgnore, "the expected ignore projects match ignored list")
	})

	t.Run("blacklist takes priority and no whitlisted projects are ignored", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "native-development",
		}

		expectedCreate := []*types.Project{
		}

		expectedDelete := []*types.Project{
			{
				Project:     "native",
				Environment: "development",
			},
			{
				Project:     "native",
				Environment: "integration",
			},
		} 

		expectedIgnore := []*types.Project{
			{
				Project:     "native",
				Environment: "production",
			},
		}

		blackWhitelist := MakeBlackWhitelist(blackWhitelistData)
		utils.Config = &types.Config{Whitelist: true}
		gotCreated,gotDeleted,gotIgnored := GenerateProjects(fakeProject, &blackWhitelist)
		assert.ElementsMatch(t,gotCreated,expectedCreate, "the expected create projects match created list ")
		assert.ElementsMatch(t,gotDeleted,expectedDelete, "the expected delete projects match deleted list ")
		assert.ElementsMatch(t,gotIgnored,expectedIgnore, "the expected ignore projects match ignored list")
	})

	t.Run("no project is created unless  explicitly defined in whitelist; blacklisted projects are deleted", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "native-production",
		}

		expectedCreate := []*types.Project{
			{
				Project:     "native",
				Environment: "production",
			},
		}

		expectedDelete := []*types.Project{
			{
				Project:     "native",
				Environment: "development",
			},
			{
				Project:     "native",
				Environment: "integration",
			},
		} 

		expectedIgnore := []*types.Project{
		}

		blackWhitelist := MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: true}
		gotCreated,gotDeleted,gotIgnored := GenerateProjects(fakeProject, &blackWhitelist)
		assert.ElementsMatch(t,gotCreated,expectedCreate, "the expected create projects match created list ")
		assert.ElementsMatch(t,gotDeleted,expectedDelete, "the expected delete projects match deleted list ")
		assert.ElementsMatch(t,gotIgnored,expectedIgnore, "the expected ignore projects match ignored list")
	})

	t.Run("ignore all projects if confimap contains invalid data", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blaaeza": "rrzerzF",
		}

		expectedCreate := []*types.Project{
		}

		expectedDelete := []*types.Project{
		} 

		expectedIgnore := []*types.Project{
			{
				Project:     "native",
				Environment: "development",
			},
			{
				Project:     "native",
				Environment: "integration",
			},
			{
				Project:     "native",
				Environment: "production",
			},
		}
		blackWhitelist := MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: true}
		gotCreated,gotDeleted,gotIgnored := GenerateProjects(fakeProject, &blackWhitelist)
		assert.ElementsMatch(t,gotCreated,expectedCreate, "the expected create projects match created list ")
		assert.ElementsMatch(t,gotDeleted,expectedDelete, "the expected delete projects match deleted list ")
		assert.ElementsMatch(t,gotIgnored,expectedIgnore, "the expected ignore projects match ignored list")
	})

	//BLACKLIST
	t.Run("Projects are created unless explicitly blacklisted", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "",
			"whitelist": "native-development",
		}

		expectedCreate := []*types.Project{
			{
				Project:     "native",
				Environment: "development",
			},
			{
				Project:     "native",
				Environment: "integration",
			},
			{
				Project:     "native",
				Environment: "production",
			},
		}

		expectedDelete := []*types.Project{
		} 

		expectedIgnore := []*types.Project{
		}

		blackWhitelist := MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: false}
		gotCreated,gotDeleted,gotIgnored := GenerateProjects(fakeProject, &blackWhitelist)
		assert.ElementsMatch(t,gotCreated,expectedCreate, "the expected create projects match created list ")
		assert.ElementsMatch(t,gotDeleted,expectedDelete, "the expected delete projects match deleted list ")
		assert.ElementsMatch(t,gotIgnored,expectedIgnore, "the expected ignore projects match ignored list")
	})



	t.Run("project don't require whitelisting to be created", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "",
		}
		expectedCreate := []*types.Project{
			{
				Project:     "native",
				Environment: "production",
			},
		}

		expectedDelete := []*types.Project{
			{
				Project:     "native",
				Environment: "development",
			},
			{
				Project:     "native",
				Environment: "integration",
			},
		} 

		expectedIgnore := []*types.Project{
		}

		blackWhitelist := MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: false}
		gotCreated,gotDeleted,gotIgnored := GenerateProjects(fakeProject, &blackWhitelist)
		assert.ElementsMatch(t,gotCreated,expectedCreate, "the expected create projects match created list ")
		assert.ElementsMatch(t,gotDeleted,expectedDelete, "the expected delete projects match deleted list ")
		assert.ElementsMatch(t,gotIgnored,expectedIgnore, "the expected ignore projects match ignored list")
	})

	t.Run("all projects are created if confimap contains invalid data", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blaaeza": "rrzerzF",
		}
		expectedCreate := []*types.Project{
			{
				Project:     "native",
				Environment: "development",
			},
			{
				Project:     "native",
				Environment: "integration",
			},
			{
				Project:     "native",
				Environment: "production",
			},
		}

		expectedDelete := []*types.Project{
		} 

		expectedIgnore := []*types.Project{
		}

		blackWhitelist := MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: false}
		gotCreated,gotDeleted,gotIgnored := GenerateProjects(fakeProject, &blackWhitelist)
		assert.ElementsMatch(t,gotCreated,expectedCreate, "the expected create projects match created list ")
		assert.ElementsMatch(t,gotDeleted,expectedDelete, "the expected delete projects match deleted list ")
		assert.ElementsMatch(t,gotIgnored,expectedIgnore, "the expected ignore projects match ignored list")
	})

}