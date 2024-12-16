package services

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
)

var DnsParser = regexp.MustCompile("(?:.+_+)*(?P<namespace>.+)_(?P<role>.+)$")

// Get Namespace, Role for a list of group name
func GetUserNamespaces(groups []string) []*types.Project {
	res := make([]*types.Project, 0)
	for _, groupname := range groups {
		tupple, err := GetUserNamespace(groupname)
		if err == nil {
			res = append(res, tupple)
		} else {
			utils.Log.Error().Msg(err.Error())
		}
	}
	return res
}

// Parse an ldap namespace an extract:
// - Kubernetes namespace
// - Project ( namespace without environment)
// - Environment
// If environment not found, return the namespace as is
func NamespaceParser(namespace string) types.Project {
	var project = types.Project{}

	if !utils.HasSuffixes(namespace, utils.AllEnvironments) {
		project.Project = namespace
		return project
	}

	splits := strings.Split(namespace, "-")
	environment := splits[len(splits)-1]
	if utils.LdapMapping[environment] != utils.Empty {
		environment = utils.LdapMapping[environment]
	}
	project.Environment = environment
	project.Project = strings.Join(splits[:len(splits)-1], "-")
	return project
}

// Get Namespace, Role for a group name
func GetUserNamespace(group string) (*types.Project, error) {

	lowerGroup := strings.ToLower(group)
	keys := DnsParser.SubexpNames()
	if len(keys) < 3 {
		return nil, fmt.Errorf("the ldap group parser does not have the two required keys (namespace and role) as it only contains %v", keys)
	}

	countSplits := len(DnsParser.FindStringSubmatch(lowerGroup))

	if countSplits != 3 {
		return nil, fmt.Errorf("cannot find a namespace and a role - the ldap group '%v' cannot be parsed", group)
	}

	rawNamespace, role := DnsParser.ReplaceAllString(lowerGroup, "${namespace}"), DnsParser.ReplaceAllString(lowerGroup, "${role}")
	project := NamespaceParser(rawNamespace)
	project.Role = role
	project.Source = group

	isNamespaceValid, err := regexp.MatchString(utils.Dns1123LabelFmt, project.Namespace())
	if err != nil {
		return nil, err
	}
	isInBlacklistedNamespace := slices.Contains(utils.BlacklistedNamespaces, project.Namespace())
	isRoleValid := slices.Contains(utils.WhitelistedRoles, project.Role)

	switch {
	case isInBlacklistedNamespace:
		return nil, fmt.Errorf("the ldap group %v cannot be created, its namespace %v is protected through blacklist", group, project.Namespace())
	case !isNamespaceValid:
		return nil, fmt.Errorf("the ldap group %v cannot be created, its namespace %v is not dns1123 compliant", group, project.Namespace())
	case !isRoleValid:
		return nil, fmt.Errorf("the ldap group %v cannot be created, its role %v is not valid", group, project.Namespace())
	case len(project.Namespace()) > utils.DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for namespace cannot exceeded %v characters", utils.DNS1123LabelMaxLength)
	case len(role) > utils.DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for role cannot exceeded %v characters", utils.DNS1123LabelMaxLength)
	default:
		return &project, nil
	}
}
