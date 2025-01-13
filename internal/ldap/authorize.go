package ldap

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ca-gip/kubi/pkg/types"
)

func isAllowed(user *types.User, regexpPatterns []string) (bool, error) {
	var allowedInCluster bool
	// To get access, the user needs at least one of the following:
	// - Be granted access to at least one project
	// - Have special rights
	// - Have their group listed in an extra group allowlist
	if len(user.ProjectAccesses) > 0 || user.IsAdmin || user.IsAppOps || user.IsCloudOps || user.IsViewer || user.IsService {
		allowedInCluster = true
	} else { // else is not mandatory it's just an optimisation: don't browse all groups if we already know the user has the rights to the cluster
		for _, groupName := range user.Groups {
			for _, pattern := range regexpPatterns {
				matched, err := regexp.MatchString(pattern, strings.ToUpper(groupName))
				if err != nil {
					return false, fmt.Errorf("error matching pattern %v: %v", pattern, err)
				}
				if matched {
					allowedInCluster = true
					break
				}
			}
		}
	}
	return allowedInCluster, nil
}
