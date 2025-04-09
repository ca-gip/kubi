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
	// We leverage the fact that the last '-' character separates
	// the projectName from the environment
	parts := regexp.MustCompile("(?P<project>.+)-(?P<env>.+)$").FindStringSubmatch(namespaceInput)

	projectName = namespaceInput
	environment = ""
	if len(parts) > 2 && slices.Contains(AllEnvironments, parts[2]) {
		environment = parts[2]
		if val, ok := EnvironmentNamesMapping[environment]; ok {
			environment = val
		}
		projectName = parts[1]
	}
	return
}

// Constructor to create a project structure based on the groupname
func NewProject(group string) (*types.Project, error) {

	lowerGroup := strings.ToLower(group)
	keys := DnsParser.SubexpNames()
	if len(keys) < 3 {
		return nil, fmt.Errorf("the group parser does not have the two required keys (namespace and role) as it only contains %v", keys)
	}

	parts := DnsParser.FindStringSubmatch(lowerGroup)

	if len(parts) != 3 {
		return nil, fmt.Errorf("cannot find a namespace and a role - the group '%v' cannot be parsed", group)
	}

	rawNamespace, role := parts[1], parts[2]
	fmt.Println("namespace:", rawNamespace, "role:", role)
	projectName, environment := parseNamespace(rawNamespace)
	project := &types.Project{
		Project:     projectName,
		Role:        role,
		Source:      group,
		Environment: environment,
	}
	projectNs := project.Namespace()
	isNamespaceValid, err := regexp.MatchString(Dns1123LabelFmt, projectNs)
	if err != nil {
		return nil, err
	}
	isInBlacklistedNamespace := slices.Contains(BlacklistedNamespaces, projectNs)
	isRoleValid := slices.Contains(WhitelistedRoles, project.Role)

	switch {
	case len(projectNs) > DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for namespace cannot exceeded %v characters", DNS1123LabelMaxLength)
	case len(role) > DNS1123LabelMaxLength:
		return nil, fmt.Errorf("the name for role cannot exceeded %v characters", DNS1123LabelMaxLength)
	case isInBlacklistedNamespace:
		return nil, fmt.Errorf("the project from group %v cannot be created, its namespace %v is protected through blacklist", group, projectNs)
	case !isNamespaceValid:
		return nil, fmt.Errorf("the project from group %v cannot be created, its namespace %v is not dns1123 compliant", group, projectNs)
	case !isRoleValid:
		return nil, fmt.Errorf("the project from group %v cannot be created, its role %v is not valid", group, role)
	default:
		return project, nil
	}
}

func GetProjectsFromGrouplist(groups []string) []*types.Project {
	projects := []*types.Project{}
	for _, projectGroup := range groups {
		project, err := NewProject(projectGroup)
		if err != nil {
			slog.Error("Could not generate project name from group name", "group", projectGroup, "reason", err)
			continue
		}
		projects = append(projects, project)
	}
	return projects
}
