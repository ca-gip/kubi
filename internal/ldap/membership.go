package ldap

import (
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type LDAPMemberships struct {
	AdminAccess         []*ldap.Entry
	AppOpsAccess        []*ldap.Entry
	CustomerOpsAccess   []*ldap.Entry
	ViewerAccess        []*ldap.Entry
	ServiceAccess       []*ldap.Entry
	CloudOpsAccess      []*ldap.Entry
	ClusterGroupsAccess []*ldap.Entry // This represents the groups that are cluster-scoped (=projects)
}

// Constructing LDAPMemberships struct with all the special groups the user is member of.
// This does not include the standard groups like "authenticated" or "system:authenticated"
// or cluster based groups.
func (c *LDAPClient) getMemberships(userDN string) (*LDAPMemberships, error) {
	m := &LDAPMemberships{}

	var err error
	m.AdminAccess, err = c.getGroupsContainingUser(c.AdminGroupBase, userDN)
	if err != nil {
		return nil, errors.Wrap(err, "error getting admin access")
	}

	m.AppOpsAccess, err = c.getGroupsContainingUser(c.AppMasterGroupBase, userDN)
	if err != nil {
		return nil, errors.Wrap(err, "error getting app ops access")
	}

	m.CustomerOpsAccess, err = c.getGroupsContainingUser(c.CustomerOpsGroupBase, userDN)
	if err != nil {
		return nil, errors.Wrap(err, "error getting customer ops access")
	}

	m.ViewerAccess, err = c.getGroupsContainingUser(c.ViewerGroupBase, userDN)
	if err != nil {
		return nil, errors.Wrap(err, "error getting viewer access")
	}

	m.ServiceAccess, err = c.getGroupsContainingUser(c.ServiceGroupBase, userDN)
	if err != nil {
		return nil, errors.Wrap(err, "error getting service access")
	}

	m.CloudOpsAccess, err = c.getGroupsContainingUser(c.OpsMasterGroupBase, userDN)
	if err != nil {
		return nil, errors.Wrap(err, "error getting cloud ops access")
	}

	// This is better than binding directly to the userDN and querying memberOf:
	// in case of nested groups or other complex group structures, the memberOf
	// attribute may not be populated correctly.
	m.ClusterGroupsAccess, err = c.getGroupsContainingUser(c.GroupBase, userDN)
	if err != nil {
		return nil, errors.Wrap(err, "error getting cluster groups access")
	}

	return m, nil
}

// toGroupNames returns a slice for all the group names the user is member of,
// rather than their full LDAP entries.
func (m *LDAPMemberships) toGroupNames() []string {
	var groups []string
	for _, entry := range m.AdminAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	for _, entry := range m.AppOpsAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	for _, entry := range m.CustomerOpsAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	for _, entry := range m.ViewerAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	for _, entry := range m.ServiceAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	for _, entry := range m.CloudOpsAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	for _, entry := range m.ClusterGroupsAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
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
