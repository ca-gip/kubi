package services

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
)

// DNSParser is a regex to parse a group name into a namespace and a role.
// Please note the underscore behaviour:
// The last one is used for parsing.
// What's after the last underscore becomes the role.
// What's before is the namespace, but only if it is a complete word
// (all the previous underscores content are removed).
var DnsParser = regexp.MustCompile("(?:.+_+)*(?P<namespace>.+)_(?P<role>.+)$")

// Parse an ldap namespace an extract:
// - Project ( namespace without environment)
// - Environment
// If environment not found, return the namespace as is
// This is a convenience function for test purposes
func namespaceParser(namespaceInput string) (projectName string, environment string) {

	var namespaceHasSuffix bool

	// check whether any of our environments names (short and longs)
	// are part of the namespace given in input
	for _, environmentSuffix := range utils.AllEnvironments {
		if strings.HasSuffix(namespaceInput, "-"+environmentSuffix) {
			namespaceHasSuffix = true
			break
		}
	}

	if !namespaceHasSuffix {
		projectName = namespaceInput
		environment = ""
		return
	}

	splits := strings.Split(namespaceInput, "-")

	environment = splits[len(splits)-1]
	if val, ok := utils.LdapMapping[environment]; ok {
		environment = val
	}

	projectName = strings.Join(splits[:len(splits)-1], "-")
	return
}

// Constructor to create a project structure based on the groupname
func NewProject(group string) (*types.Project, error) {

	lowerGroup := strings.ToLower(group)
	keys := DnsParser.SubexpNames()
	if len(keys) < 3 {
		return nil, fmt.Errorf("the group parser does not have the two required keys (namespace and role) as it only contains %v", keys)
	}

	countSplits := len(DnsParser.FindStringSubmatch(lowerGroup))

	if countSplits != 3 {
		return nil, fmt.Errorf("cannot find a namespace and a role - the group '%v' cannot be parsed", group)
	}

	rawNamespace, role := DnsParser.ReplaceAllString(lowerGroup, "${namespace}"), DnsParser.ReplaceAllString(lowerGroup, "${role}")
	fmt.Println("namespace:", rawNamespace, "role:", role)
	projectName, environment := namespaceParser(rawNamespace)
	project := &types.Project{
		Project:     projectName,
		Role:        role,
		Source:      group,
		Environment: environment,
	}

	isNamespaceValid, err := regexp.MatchString(utils.Dns1123LabelFmt, project.Namespace())
	if err != nil {
		return nil, err
	}
	isInBlacklistedNamespace := slices.Contains(utils.BlacklistedNamespaces, project.Namespace())
	isRoleValid := slices.Contains(utils.WhitelistedRoles, project.Role)

	switch {
	case len(project.Namespace()) > utils.DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for namespace cannot exceeded %v characters", utils.DNS1123LabelMaxLength)
	case len(role) > utils.DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for role cannot exceeded %v characters", utils.DNS1123LabelMaxLength)
	case isInBlacklistedNamespace:
		return nil, fmt.Errorf("the project from group %v cannot be created, its namespace %v is protected through blacklist", group, project.Namespace())
	case !isNamespaceValid:
		return nil, fmt.Errorf("the project from group %v cannot be created, its namespace %v is not dns1123 compliant", group, project.Namespace())
	case !isRoleValid:
		return nil, fmt.Errorf("the project from group %v cannot be created, its role %v is not valid", group, role)
	default:
		return project, nil
	}
}

// GetAllProjects returns a slice of new projects from a list of groups
// This is useful to see all the projects matching all the groups from the luster
// Or to see all the projects a user has access to (based on the user's groups)
func GetAllProjects(groups []string) []*types.Project {
	res := make([]*types.Project, 0)
	for _, groupname := range groups {
		tupple, err := NewProject(groupname)
		if err == nil {
			res = append(res, tupple)
		} else {
			utils.Log.Error().Msg(err.Error())
		}
	}
	return res
}
