package ldap

import (
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type UserMemberships struct {
	AdminAccess         []*ldap.Entry
	AppOpsAccess        []*ldap.Entry
	CustomerOpsAccess   []*ldap.Entry
	ViewerAccess        []*ldap.Entry
	ServiceAccess       []*ldap.Entry
	CloudOpsAccess      []*ldap.Entry
	ClusterGroupsAccess []*ldap.Entry // This represents the groups that are cluster-scoped (=projects)
}

// Constructing UserMemberships struct with all the special groups the user is member of.
// This does not include the standard groups like "authenticated" or "system:authenticated"
// or cluster based groups.
func (m *UserMemberships) FromUserDN(userDN string) error {
	var err error
	m.AdminAccess, err = getGroupsContainingUser(utils.Config.Ldap.AdminGroupBase, userDN)
	if err != nil {
		return errors.Wrap(err, "error getting admin access")
	}

	m.AppOpsAccess, err = getGroupsContainingUser(utils.Config.Ldap.AppMasterGroupBase, userDN)
	if err != nil {
		return errors.Wrap(err, "error getting app ops access")
	}

	m.CustomerOpsAccess, err = getGroupsContainingUser(utils.Config.Ldap.CustomerOpsGroupBase, userDN)
	if err != nil {
		return errors.Wrap(err, "error getting customer ops access")
	}

	m.ViewerAccess, err = getGroupsContainingUser(utils.Config.Ldap.ViewerGroupBase, userDN)
	if err != nil {
		return errors.Wrap(err, "error getting viewer access")
	}

	m.ServiceAccess, err = getGroupsContainingUser(utils.Config.Ldap.ServiceGroupBase, userDN)
	if err != nil {
		return errors.Wrap(err, "error getting service access")
	}

	m.CloudOpsAccess, err = getGroupsContainingUser(utils.Config.Ldap.OpsMasterGroupBase, userDN)
	if err != nil {
		return errors.Wrap(err, "error getting cloud ops access")
	}

	// This is better than binding directly to the userDN and querying memberOf:
	// in case of nested groups or other complex group structures, the memberOf
	// attribute may not be populated correctly.
	m.ClusterGroupsAccess, err = getGroupsContainingUser(utils.Config.Ldap.GroupBase, userDN)
	if err != nil {
		return errors.Wrap(err, "error getting cluster groups access")
	}

	return nil
}

// ListGroups retuns a slice for all the group names the user is member of,
// rather than their full LDAP entries.
func (m *UserMemberships) ListGroups() []string {
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
	groups = append(groups, m.ListClusterGroups()...)
	return groups
}

// ListClusterGroups is a convenience method to return the cluster-scoped groups
// rather than full membership entries.
func (m *UserMemberships) ListClusterGroups() []string {
	var groups []string
	for _, entry := range m.ClusterGroupsAccess {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups
}

func getGroupsContainingUser(groupBaseDN string, userDN string) ([]*ldap.Entry, error) {
	if len(groupBaseDN) == 0 {
		return []*ldap.Entry{}, nil
	}
	req := ldap.NewSearchRequest(
		groupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)

	res, err := ldapQuery(*req)
	if err != nil {
		return nil, errors.Wrap(err, "error querying for group memberships")
	}

	return res.Entries, nil
}

// Get All groups for the cluster from LDAP
func GetAllGroups() ([]string, error) {

	request := &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.GroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       "(|(objectClass=groupOfNames)(objectClass=group))", // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}

	results, err := ldapQuery(*request)
	if err != nil {
		return nil, errors.Wrap(err, "Error searching all groups")
	}

	var groups []string
	for _, entry := range results.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}
