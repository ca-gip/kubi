package project

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/ca-gip/kubi/pkg/types"
)

type ProjectLister interface {
	ListProjects() ([]*types.Project, error)
}

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
func parseNamespace(namespaceInput string) (projectName string, environment string) {

	var namespaceHasSuffix bool

	// check whether any of our environments names (short and longs)
	// are part of the namespace given in input
	for _, environmentSuffix := range AllEnvironments {
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
	if val, ok := EnvironmentNamesMapping[environment]; ok {
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
	projectName, environment := parseNamespace(rawNamespace)
	project := &types.Project{
		Project:     projectName,
		Role:        role,
		Source:      group,
		Environment: environment,
	}

	isNamespaceValid, err := regexp.MatchString(Dns1123LabelFmt, project.Namespace())
	if err != nil {
		return nil, err
	}
	isInBlacklistedNamespace := slices.Contains(BlacklistedNamespaces, project.Namespace())
	isRoleValid := slices.Contains(WhitelistedRoles, project.Role)

	switch {
	case len(project.Namespace()) > DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for namespace cannot exceeded %v characters", DNS1123LabelMaxLength)
	case len(role) > DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for role cannot exceeded %v characters", DNS1123LabelMaxLength)
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

func GetProjectsFromGrouplist(groups []string) []*types.Project {
	projects := make([]*types.Project, 0)
	for _, projectGroup := range groups {
		project, err := NewProject(projectGroup)
		if err != nil {
			slog.Error(fmt.Sprintf("Could not generate project name from group %v", projectGroup))
			continue
		}
		projects = append(projects, project)
	}
	return projects
}
