package ldap

import (
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

// getProjectGroups returns all groupnames that are useful for projects.
func (c *LDAPClient) getProjectGroups() ([]string, error) {

	request := &ldap.SearchRequest{
		BaseDN:       c.GroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       "(|(objectClass=groupOfNames)(objectClass=group))", // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}

	results, err := c.Query(*request)
	if err != nil {
		return nil, errors.Wrap(err, "Error searching all groups")
	}

	var groups []string
	for _, entry := range results.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}
