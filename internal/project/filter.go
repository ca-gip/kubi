package project

import (
	"slices"
	"strings"

	"github.com/ca-gip/kubi/pkg/types"
)

// FilterProjects filters projects based on the black and whitelist
func FilterProjects(whitelistEnabled bool, context []*types.Project, blackWhiteList *types.BlackWhitelist) ([]*types.Project, []*types.Project, []*types.Project) {

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
		case whitelistEnabled && isWhitelisted:
			createdProjects = append(createdProjects, auth)
		//project will be ignored if whitelist  is enabled and project not present on whitelisted projects
		case whitelistEnabled && !isWhitelisted:
			ignoredProjects = append(ignoredProjects, auth)
		//project will be created if whitelist is disabled and no projects in blacklist
		case !whitelistEnabled:
			createdProjects = append(createdProjects, auth)
		}
	}

	return createdProjects, deletedProjects, ignoredProjects
}

func MakeBlackWhitelist(blackWhiteCMData map[string]string) types.BlackWhitelist {

	blackWhiteList := types.BlackWhitelist{
		Blacklist: strings.Split(blackWhiteCMData["blacklist"], ","),
		Whitelist: strings.Split(blackWhiteCMData["whitelist"], ","),
	}

	return blackWhiteList

}
