package services

import (
	"errors"
	"fmt"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"regexp"
	"strings"
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
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group parser doesn't have the two mandatory key: namespace and role,
			you have only this: %v")
			 `, keys))
	}

	countSplits := len(DnsParser.FindStringSubmatch(lowerGroup))

	if countSplits != 3 {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group '%v', cannot be parse. Can't find a namespace and a role'
			 `, group))
	}

	rawNamespace, role := DnsParser.ReplaceAllString(lowerGroup, "${namespace}"), DnsParser.ReplaceAllString(lowerGroup, "${role}")
	project := NamespaceParser(rawNamespace)
	project.Role = role
	project.Source = lowerGroup

	isNamespaceValid, _ := regexp.MatchString(utils.Dns1123LabelFmt, project.Namespace())
	isRoleValid := utils.Index(utils.WhitelistedRoles, project.Role) != -1

	if utils.Index(utils.BlacklistedNamespaces, project.Namespace()) != -1 {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group %v, cannot be created. 
			The namespace %v is protected.`, group, project.Namespace()))
	} else if !isNamespaceValid {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group %v, cannot be created. 
			The namespace %v is not dns1123 compliant.`, group, project.Namespace()))
	} else if !isRoleValid {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group %v, cannot be created. 
			The role %v is not valid.`, group, project.Namespace()))
	} else if len(project.Namespace()) > utils.DNS1123LabelMaxLength {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The name for namespace cannot exceeded %v characters.`, utils.DNS1123LabelMaxLength))
	} else if len(role) > utils.DNS1123LabelMaxLength {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The name for role cannot exceeded %v characters.`, utils.DNS1123LabelMaxLength))
	} else {
		return &project, nil
	}
}
