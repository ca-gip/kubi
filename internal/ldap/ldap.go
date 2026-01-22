package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/ca-gip/kubi/internal/project"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

// This is the internal API for LDAP auth.
// The rest of the implementation is in the internal/ldap package.

type LDAPClient struct {
	types.LdapConfig
}

func NewLDAPClient(config types.LdapConfig) *LDAPClient {
	return &LDAPClient{
		config,
	}
}

// ListProjects Implement ProjectLister interface to be able to replace with a list of projects for testing.
func (c *LDAPClient) ListProjects() ([]*types.Project, error) {
	// todo fix this long standing bug of view and ops groups not being filtered.
	allClusterGroups, err := c.getProjectGroups()
	if err != nil {
		return nil, fmt.Errorf("get Project groups failed, preventing to List Projects: %v", err)
	}
	if len(allClusterGroups) == 0 {
		return nil, fmt.Errorf("no ldap groups found")
	}
	return project.GetProjectsFromGrouplist(allClusterGroups), nil
}

// getProjectGroups returns all groupnames that are useful for projects.
func (c *LDAPClient) getProjectGroups() ([]string, error) {

	request := &ldap.SearchRequest{
		BaseDN:       c.GroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
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
	for _, entry := range results {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// Connect to LDAP and bind with given credentials
func (c *LDAPClient) ldapConnectAndBind(login string, password string) (*ldap.Conn, error) {
	var (
		err  error
		conn *ldap.Conn
	)
	tlsConfig := &tls.Config{
		ServerName:         c.Host,
		InsecureSkipVerify: c.SkipTLSVerification,
	}

	switch {
	case c.UseSSL:
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), tlsConfig)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to create ldap tcp connection for %s:%d", c.Host, c.Port)
		}
	case c.StartTLS:
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port))
		if err != nil {
			return nil, errors.Wrapf(err, "unable to create ldap tcp connection for %s:%d", c.Host, c.Port)
		}
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to setup TLS connection")
		}
	default:
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port))
		if err != nil {
			return nil, errors.Wrapf(err, "unable to create INSECURE ldap tcp connection for %s:%d", c.Host, c.Port)
		}
	}

	// Bind with BindAccount
	err = conn.Bind(login, password)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return conn, nil
}

// Query LDAP with default credentials and paging parameters
func (c *LDAPClient) Query(request ldap.SearchRequest) ([]*ldap.Entry, error) {
	conn, err := c.ldapConnectAndBind(c.BindDN, c.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	results, err := conn.SearchWithPaging(&request, c.PageSize)
	if err != nil {
		return nil, fmt.Errorf("error searching in LDAP with request %v, %v", request, err)
	}
	return results.Entries, err
}
