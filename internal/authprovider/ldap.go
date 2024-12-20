package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
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

// Query LDAP with default credentials and paging parameters
func ldapQuery(request ldap.SearchRequest) (*ldap.SearchResult, error) {
	conn, err := ldapConnectAndBind(utils.Config.Ldap.BindDN, utils.Config.Ldap.BindPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	results, err := conn.SearchWithPaging(&request, utils.Config.Ldap.PageSize)
	if err != nil {
		return nil, fmt.Errorf("error searching in LDAP with request %v, %v", request, err)
	}
	return results, nil

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

// Authenticate a user through LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occurred
func AuthenticateUser(username string, password string) (types.User, error) {

	// Get User Distinguished Name for Standard User
	user, err := validateUserCredentials(utils.Config.Ldap.UserBase, username, password)
	if err == nil {
		return user, nil
	}

	// Now handling errors to get standard user, falling back to admin user, if
	// config allows it
	if len(utils.Config.Ldap.AdminUserBase) <= 0 {
		return types.User{}, fmt.Errorf("cannot find user %s in LDAP", username)
	}

	// Retry as admin
	user, err = validateUserCredentials(utils.Config.Ldap.AdminUserBase, username, password)
	if err != nil {
		return types.User{}, fmt.Errorf("cannot find admin user %s in LDAP", username)
	}
	return user, nil
}

// Finds an user and check if its password is correct.
func validateUserCredentials(base string, username string, password string) (types.User, error) {
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, fmt.Sprintf(utils.Config.Ldap.UserFilter, username), []string{"dn", "mail"}, nil)

	conn, err := ldapConnectAndBind(utils.Config.Ldap.BindDN, utils.Config.Ldap.BindPassword)
	if err != nil {
		return types.User{}, err
	}
	defer conn.Close()

	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	switch {
	case err != nil:
		return types.User{}, fmt.Errorf("error searching for user %s, %w", username, err)
	case len(res.Entries) == 0:
		return types.User{}, fmt.Errorf("no result for the user search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		return types.User{}, fmt.Errorf("multiple entries found for the user search filter '%s'", req.Filter)
	}

	userDN := res.Entries[0].DN
	mail := res.Entries[0].GetAttributeValue("mail")
	user := types.User{
		Username: username,
		UserDN:   userDN,
		Email:    mail,
	}

	_, err = ldapConnectAndBind(userDN, password)
	if err != nil {
		return types.User{}, fmt.Errorf("cannot authenticate user %s in LDAP", username)
	}
	return user, nil
}

// Connect to LDAP and bind with given credentials
func ldapConnectAndBind(login string, password string) (*ldap.Conn, error) {
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

	if utils.Config.Ldap.StartTLS {
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to setup TLS connection")
		}
	}

	if err != nil {
		return nil, errors.Wrapf(err, "unable to create ldap connector for %s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port)
	}

	// Bind with BindAccount
	err = conn.Bind(login, password)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return conn, nil
}
