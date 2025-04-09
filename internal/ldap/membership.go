package ldap

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"gopkg.in/ldap.v2"
)

type LDAPMemberships struct {
	AdminAccess         []*ldap.Entry // Contains the groups considered for admin, to be removed in the future
	AppOpsAccess        []*ldap.Entry
	CustomerOpsAccess   []*ldap.Entry
	ViewerAccess        []*ldap.Entry
	ServiceAccess       []*ldap.Entry
	CloudOpsAccess      []*ldap.Entry
	ClusterGroupsAccess []*ldap.Entry // This represents the groups that are cluster-scoped (=projects)
	NonSpecificGroups   []*ldap.Entry // This contains all the non-specific and non-project groups, unfiltered.
}

// Constructing LDAPMemberships struct with all the special groups the user is member of.
// This does not include the standard groups like "authenticated" or "system:authenticated"
// or cluster based groups.
func (c *LDAPClient) getMemberships(userDN string) (*LDAPMemberships, error) {
	m := &LDAPMemberships{}

	var err error

	// TODO Evaluate whether we could use the memberOf of userDN instead.
	entries, err := c.getGroupsContainingUser(c.AllGroupsBase, userDN)
	if err != nil {
		return nil, fmt.Errorf("could not get groups %v", err)
	}
	// special groups, to be removed when we're ready to do so.
	for _, entry := range entries {
		switch strings.ToUpper(entry.DN) {
		// The following will be able to get removed when we will
		// have removed the specific accesses.
		case strings.ToUpper(c.AdminGroupBase):
			m.AdminAccess = append(m.AdminAccess, entry)
		case strings.ToUpper(c.AppMasterGroupBase):
			m.AppOpsAccess = append(m.AppOpsAccess, entry)
		case strings.ToUpper(c.CustomerOpsGroupBase):
			m.CustomerOpsAccess = append(m.CustomerOpsAccess, entry)
		case strings.ToUpper(c.ViewerGroupBase):
			m.ViewerAccess = append(m.ViewerAccess, entry)
		case strings.ToUpper(c.ServiceGroupBase):
			m.ServiceAccess = append(m.ServiceAccess, entry)
		case strings.ToUpper(c.OpsMasterGroupBase):
			m.CloudOpsAccess = append(m.CloudOpsAccess, entry)
		case strings.ToUpper(c.GroupBase):
			m.ClusterGroupsAccess = append(m.ClusterGroupsAccess, entry)
		default:
			m.NonSpecificGroups = append(m.NonSpecificGroups, entry)
		}
	}
	return m, nil
}

// toGroupNames returns a slice for all the group names the user is member of,
// rather than their full LDAP entries.
// Ensuring uniqueness through map of 0 bytes structs as sets do not exist in go std lib
// This is necessary, because we know the groups in specific access (like adminAccess)
// are also present in the big blob of groups (="NonSpecificGroups")
func (m *LDAPMemberships) toGroupNames() []string {
    groupMap := make(map[string]struct{})

    accessCategories := [][]*ldap.Entry{
        m.AdminAccess,
        m.AppOpsAccess,
        m.CustomerOpsAccess,
        m.ViewerAccess,
        m.ServiceAccess,
        m.CloudOpsAccess,
        m.ClusterGroupsAccess,
        m.NonSpecificGroups,
    }

    for _, category := range accessCategories {
        for _, entry := range category {
            groupMap[entry.GetAttributeValue("cn")] = struct{}{}
        }
    }
    groups := make([]string, 0, len(groupMap))
    for group := range groupMap {
        groups = append(groups, group)
    }

    return groups
}

// toProjectNames retuns a slice for all the project names the user is member of,
// rather than their full LDAP entries. This is not returning a slice of the projects.
func (m *LDAPMemberships) toProjectNames() []string {
	var groups []string
	for _, entry := range m.ClusterGroupsAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups
}

func (m *LDAPMemberships) isUserAllowedOnCluster(regexpPatterns []string) (bool, error) {
	var allowedInCluster bool
	// To get access, the user needs at least one of the following:
	// - Be granted access to at least one project
	// - Have special rights
	// - Have their group listed in an extra group allowlist
	if len(m.AdminAccess) > 0 || len(m.AppOpsAccess) > 0 || len(m.CustomerOpsAccess) > 0 || len(m.ViewerAccess) > 0 || len(m.ServiceAccess) > 0 || len(m.CloudOpsAccess) > 0 || len(m.ClusterGroupsAccess) > 0 {
		allowedInCluster = true
	} else { // else is not mandatory it's just an optimisation: don't browse all groups if we already know the user has the rights to the cluster
		for _, groupName := range m.NonSpecificGroups {
			for _, pattern := range regexpPatterns {
				matched, err := regexp.MatchString(strings.ToUpper(pattern), strings.ToUpper(groupName.DN)) // we match on full DN rather than CN because nobody prevents the ppl in the different entities to create a CN identical as the one used for adminGroup. This is purely out of precaution. In the future, we might want to change the regexp to match only the cn of the groups if we have the guarantee the users will not create groups that are duplicate.
				if err != nil {
					return false, fmt.Errorf("error matching pattern %v: %v", pattern, err)
				}
				slog.Info("Result of regexp match between config pattern and the following user's group", "match", matched, "pattern", pattern, "groupDN", groupName.DN)
				if matched {
					allowedInCluster = true
					break
				}
			}
			if allowedInCluster {
				slog.Info("not evaluating further group patterns, the user has access to the cluster")
				break
			}
		}
	}
	return allowedInCluster, nil
}
