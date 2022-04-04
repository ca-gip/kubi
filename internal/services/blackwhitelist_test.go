package services_test

import (
	"encoding/json"
	"testing"

	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	v12 "github.com/ca-gip/kubi/pkg/apis/ca-gip/v1"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBlackWhiteList(t *testing.T) {

	fakeProjectJson := []byte(`{
		"apiVersion": "ca-gip.github.com/v1",
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

		result := services.MakeBlackWhitelist(nil)
		assert.Equal(t, []string([]string{""}), result.Blacklist)
		assert.Equal(t, []string([]string{""}), result.Whitelist)
	})

	t.Run("with_empty_map", func(t *testing.T) {
		blackWhitelistData := map[string]string{}

		result := services.MakeBlackWhitelist(blackWhitelistData)
		assert.Equal(t, []string([]string{""}), result.Blacklist)
		assert.Equal(t, []string([]string{""}), result.Whitelist)
	})

	t.Run("with_non_sense_data", func(t *testing.T) {
		blackWhitelistData := map[string]string{
			"blacldzada":    "dzadzdaz",
			"dzadz$Ùdzadza": "fefezfez, 6z556/*/R/ÉR*/",
		}

		result := services.MakeBlackWhitelist(blackWhitelistData)
		assert.Equal(t, []string([]string{""}), result.Blacklist)
		assert.Equal(t, []string([]string{""}), result.Whitelist)
	})

	t.Run("with_real_data", func(t *testing.T) {
		blackWhitelistData := map[string]string{
			"blacklist": "native-developpement, native-integration",
			"whitelist": "",
		}

		result := services.MakeBlackWhitelist(blackWhitelistData)
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
	}

	//WHITELIST
	t.Run("with_empty_whitelist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: true}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{false}, result)
	})

	t.Run("with_equal_whitelist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "native-development",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: true}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{true}, result)
	})

	t.Run("with_not_equal_whitelist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "native-divelopment",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: true}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{false}, result)
	})

	t.Run("with_faildata_whitelist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blaaeza": "rrzerzF",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: true}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{false}, result)
	})

	//BLACKLIST
	t.Run("with_empty_blacklist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "",
			"whitelist": "native-development",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: false}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{false}, result)
	})

	t.Run("with_equal_blacklist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-development,native-integration",
			"whitelist": "native-development",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: false}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{true}, result)
	})

	t.Run("with_not_equal_blacklist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blacklist": "native-devilopment,native-integration",
			"whitelist": "native-divelopment",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: false}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{false}, result)
	})

	t.Run("with_faildata_blacklist", func(t *testing.T) {

		blackWhitelistData := map[string]string{
			"blaaeza": "rrzerzF",
		}

		blackWhitelist := services.MakeBlackWhitelist(blackWhitelistData)

		utils.Config = &types.Config{Whitelist: false}
		result := GenerateProjects(fakeProject, &blackWhitelist)
		assert.Equal(t, []bool{false}, result)
	})

}

// Mock of GenerateProjects func from provisionner. TODO : refacto to be testable
func GenerateProjects(context []*types.Project, blackWhiteList *types.BlackWhitelist) []bool {

	var boolList []bool

	for _, auth := range context {

		// if whitelist boolean set we search namespace in configmap whitelist
		if utils.Config.Whitelist { // if configmap with whitelist exist and not empty
			if blackWhiteList.Whitelist[0] != "" && utils.Include(blackWhiteList.Whitelist, auth.Namespace()) {
				utils.Log.Info().Msgf("Project %s is whitelisted", auth.Namespace())
				boolList = append(boolList, true)
			} else {
				utils.Log.Error().Msgf("Cannot find project %s in whitelist", auth.Namespace())
				boolList = append(boolList, false)
			}
		} else if blackWhiteList.Blacklist[0] != "" { // if configmap with blacklist exist and not empty
			if utils.Include(blackWhiteList.Blacklist, auth.Namespace()) {
				utils.Log.Info().Msgf("delete project %s in blacklist", auth.Namespace())
				boolList = append(boolList, true)
			} else {
				utils.Log.Info().Msgf("Cannot find project %s in blacklist", auth.Namespace())
				boolList = append(boolList, false)
			}
		} else { // if configmap not exist and bool whitelist is false
			boolList = append(boolList, false)
		}

	}

	return boolList
}
