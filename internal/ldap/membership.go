package ldap

import (
	"fmt"
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
		if group, exists := groupMapping[upperDN]; exists {
			*group = append(*group, entry)
		} else {
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
	for _, entry := range m.AdminAccess {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}
	for _, entry := range m.AppOpsAccess {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}
	for _, entry := range m.CustomerOpsAccess {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}
	for _, entry := range m.ViewerAccess {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}
	for _, entry := range m.ServiceAccess {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}
	for _, entry := range m.CloudOpsAccess {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}
	for _, entry := range m.ClusterGroupsAccess {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}
	for _, entry := range m.NonSpecificGroups {
		groupMap[entry.GetAttributeValue("cn")] = struct{}{}
	}

	var groups []string
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
