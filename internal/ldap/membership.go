package ldap

import (
	"fmt"
	"log/slog"
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

	// Fetch all groups containing the user
	entries, err := c.getGroupsContainingUser(userDN)
	if err != nil {
		return nil, fmt.Errorf("could not get groups: %w", err)
	}

	// Categorize groups based on their DN
	groupMapping := map[string]*[]*ldap.Entry{
		strings.ToUpper(c.AdminGroupBase):       &m.AdminAccess,
		strings.ToUpper(c.AppMasterGroupBase):   &m.AppOpsAccess,
		strings.ToUpper(c.CustomerOpsGroupBase): &m.CustomerOpsAccess,
		strings.ToUpper(c.ViewerGroupBase):      &m.ViewerAccess,
		strings.ToUpper(c.ServiceGroupBase):     &m.ServiceAccess,
		strings.ToUpper(c.OpsMasterGroupBase):   &m.CloudOpsAccess,
		strings.ToUpper(c.GroupBase):            &m.ClusterGroupsAccess,
	}

	for _, entry := range entries {
		upperDN := strings.ToUpper(entry.DN)
		collected := false
		for groupBase, groups := range groupMapping {
			hasSuffix := strings.HasSuffix(upperDN, groupBase)
			if hasSuffix {
				*groups = append(*groups, entry)
				collected = true
				break
			}
		}
		if !collected {
			slog.Info(fmt.Sprintf("Couldn't collect %+v", entry))
			m.NonSpecificGroups = append(m.NonSpecificGroups, entry)
		}
	}

	return m, nil
}

// toGroupNames returns a slice for all the group names (DN) the user is member of,
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
			normalizedGroup := NormalizeGroupName(entry.DN)
			groupMap[normalizedGroup] = struct{}{}
		}
	}

	groups := make([]string, 0, len(groupMap))
	for group := range groupMap {
		groups = append(groups, group)
	}

	return groups
}

// Normalized group names will be used as subjects of k8s rolebindings
// While ldap entry are not case-sensitive, k8s subjects are, so we
// need to normalize the ldap entry so as to be robust to case or whitespace
func NormalizeGroupName(groupName string) string {
	withoutWhitespace := strings.ReplaceAll(groupName, " ", "")
	return strings.ToUpper(withoutWhitespace)
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

func (m *LDAPMemberships) isUserAllowedOnCluster() bool {
	// To get access, the user needs at least one of the following:
	return (len(m.AdminAccess) > 0 || // - Have special rights
		len(m.AppOpsAccess) > 0 || // - Have special rights
		len(m.CustomerOpsAccess) > 0 || // - Have special rights
		len(m.ViewerAccess) > 0 || // - Have special rights
		len(m.ServiceAccess) > 0 || // - Have special rights
		len(m.CloudOpsAccess) > 0 || // - Have special rights
		len(m.ClusterGroupsAccess) > 0 || //- Be granted access to at least one project
		len(m.NonSpecificGroups) > 0) // Be member of a group eligible to rolebindings
}
