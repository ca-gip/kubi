package ldap

import (
	"crypto/tls"
	"fmt"
	"github.com/ca-gip/kubi/utils"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

type Authenticator struct {
}

// Authenticate a user throug LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occured
func GetUserGroups(userDN string) ([]string, error) {

	// First TCP connect
	conn, err := getBindedConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	request := newUserGroupSearchRequest(userDN)
	results, err := conn.Search(request)

	if err != nil {
		return nil, errors.Wrapf(err, "error searching for user's group for %s", userDN)
	}

	groups := []string{}
	for _, entry := range results.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// Authenticate a user throug LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occured
func GetAllGroups() ([]string, error) {

	// First TCP connect
	conn, err := getBindedConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	request := newGroupSearchRequest()
	results, err := conn.Search(request)

	if err != nil {
		return nil, errors.Wrap(err, "Error searching all groups")
	}

	groups := []string{}
	for _, entry := range results.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// Authenticate a user throug LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occured
func AuthenticateUser(username string, password string) (*string, error) {

	// First TCP connect
	conn, err := getBindedConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get User Distinguished Name
	userDN, err := getUserDN(conn, username)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// authenticate user
	err = conn.Bind(userDN, password)
	if err != nil {
		return nil, errors.WithStack(err)
	} else {
		return &userDN, nil
	}
}

func getBindedConnection() (*ldap.Conn, error) {
	var (
		err  error
		conn *ldap.Conn
	)

	tlsConfig := &tls.Config{
		ServerName:         utils.Config.Ldap.Host,
		InsecureSkipVerify: utils.Config.Ldap.SkipTLSVerification,
	}

	if utils.Config.Ldap.UseSSL {
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port), tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port))
	}

	if utils.Config.Ldap.UseSSL {
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to setup TLS connection")
		}
	}

	if err != nil {
		return nil, errors.Wrapf(err, "unable to create ldap connector for %s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port)
	}

	// Bind with BindAccount
	err = conn.Bind(utils.Config.Ldap.BindDN, utils.Config.Ldap.BindPassword)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return conn, nil
}

// Get User DN for searching in group
func getUserDN(conn *ldap.Conn, username string) (string, error) {
	req := newUserSearchRequest(username)

	res, err := conn.Search(req)
	if err != nil {
		return "", errors.Wrapf(err, "error searching for user %s", username)
	}

	if len(res.Entries) == 0 {
		return "", errors.Errorf("No result for the user search filter '%s'", req.Filter)
	} else if len(res.Entries) > 1 {
		return "", errors.Errorf("Multiple entries found for the user search filter '%s'", req.Filter)
	}
	userDN := res.Entries[0].DN
	return userDN, nil
}

// request to search user
func newUserSearchRequest(username string) *ldap.SearchRequest {
	userFilter := fmt.Sprintf(utils.Config.Ldap.UserFilter, username)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.UserBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    2, // limit number of entries in result
		TimeLimit:    10,
		TypesOnly:    false,
		Filter:       userFilter, // filter default format : (&(objectClass=person)(uid=%s))
	}
}

// request to get user group list
func newUserGroupSearchRequest(userDN string) *ldap.SearchRequest {
	groupFilter := fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.GroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       groupFilter, // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}
}

// request to get group list ( for all namespaces )
func newGroupSearchRequest() *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.GroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       "(|(objectClass=groupOfNames)(objectClass=group))", // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}
}
