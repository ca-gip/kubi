package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

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

	var allResults []*ldap.Entry
	for {
		results, err := conn.SearchWithPaging(&request, c.PageSize)
		if err != nil {
			return nil, fmt.Errorf("error searching in LDAP with request %v, %v", request, err)
		}
		allResults = append(allResults, results.Entries...)
		if len(results.Entries) < int(c.PageSize) {
			break
		}
		request.Controls = results.Controls
	}
	return allResults, nil
}

func (c *LDAPClient) getGroupsContainingUser(groupBaseDN string, userDN string) ([]*ldap.Entry, error) {
	if len(groupBaseDN) == 0 {
		return []*ldap.Entry{}, nil
	}
	req := ldap.NewSearchRequest(
		groupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)

	res, err := c.Query(*req)
	if err != nil {
		return nil, errors.Wrap(err, "error querying for group memberships")
	}

	return res, nil
}
