package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"gopkg.in/ldap.v2"
)

type Authenticator struct {
}

// Authenticate a user through LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occurred
func GetUserGroups(userDN string) ([]string, error) {

	// First TCP connect
	conn, err := getBindedConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	request := newUserGroupSearchRequest(userDN)
	results, err := conn.SearchWithPaging(request, utils.Config.Ldap.PageSize)

	if err != nil {
		return nil, errors.Wrapf(err, "error searching for user's group for %s", userDN)
	}

	var groups []string
	for _, entry := range results.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// Authenticate a user through LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occurred
func GetAllGroups() ([]string, error) {

	conn, err := getBindedConnection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	request := newGroupSearchRequest()
	results, err := conn.SearchWithPaging(request, utils.Config.Ldap.PageSize)

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
func AuthenticateUser(username string, password string) (*string, *string, error) {

	if len(password) == 0 {
		return nil, nil, errors.New("Empty password, you must give a password.")
	}

	// Get User Distinguished Name for Standard User
	userDN, mail, err := getUserDN(utils.Config.Ldap.UserBase, username)

	if err == nil {
		return &userDN, &mail, checkAuthenticate(userDN, password)
	} else if len(utils.Config.Ldap.AdminUserBase) > 0 {
		userDN, _, err := getUserDN(utils.Config.Ldap.AdminUserBase, username)
		if err != nil {
			return &userDN, &mail, err
		}
		return &userDN, &mail, checkAuthenticate(userDN, password)
	} else {
		utils.Log.Error().Msg(err.Error())
		return nil, &mail, err
	}
}

func checkAuthenticate(userDN string, password string) error {
	conn, err := getBindedConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

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
			utils.Log.Error().Err(errors.Wrapf(err, "unable to setup TLS connection"))
			return err
		}
	}

	if err != nil {
		utils.Log.Error().Err(errors.Wrapf(err, "unable to create ldap connector for %s:%d", utils.Config.Ldap.Host, utils.Config.Ldap.Port))
		return err
	}

	// Bind with BindAccount
	err = conn.Bind(userDN, password)
	return err
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
	err = conn.Bind(utils.Config.Ldap.BindDN, utils.Config.Ldap.BindPassword)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return conn, nil
}

// Get User DN for searching in group
func getUserDN(userBaseDN string, username string) (string, string, error) {
	// First TCP connect
	conn, err := getBindedConnection()
	if err != nil {
		return utils.Empty, utils.Empty, err
	}
	defer conn.Close()

	req := newUserSearchRequest(userBaseDN, username)

	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	if err != nil {
		return utils.Empty, utils.Empty, errors.Wrapf(err, "Error searching for user %s", username)
	}

	if len(res.Entries) == 0 {
		return utils.Empty, utils.Empty, errors.Errorf("No result for the user search filter '%s'", req.Filter)

	} else if len(res.Entries) > 1 {
		return utils.Empty, utils.Empty, errors.Errorf("Multiple entries found for the user search filter '%s'", req.Filter)
	}

	userDN := res.Entries[0].DN
	mail := res.Entries[0].GetAttributeValue("mail")
	return userDN, mail, nil
}

// Check if a user is in admin LDAP group
// return true if it belong to AdminGroup, false otherwise
func HasAdminAccess(userDN string) bool {

	// No need to go further, there is no Admin Group Base
	if len(utils.Config.Ldap.AdminGroupBase) == 0 {
		return false
	}

	conn, err := getBindedConnection()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return false
	}
	defer conn.Close()

	req := newUserAdminSearchRequest(userDN)
	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	return err == nil && len(res.Entries) > 0
}

// Return true if the user manage application at cluster wide scope
func HasApplicationAccess(userDN string) bool {
	return hasApplicationAccess(userDN) || hasCustomerOpsAccess(userDN)
}

// Check if a user is in admin LDAP group
// return true if it belong to ApplicationGroup, false otherwise
func hasApplicationAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.AppMasterGroupBase) == 0 {
		return false
	}

	conn, err := getBindedConnection()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return false
	}
	defer conn.Close()

	req := newUserApplicationSearchRequest(userDN)
	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	return err == nil && len(res.Entries) > 0
}

// Check if a user is in viewer LDAP group
// return true if it belong to viewerGroup, false otherwise
func HasViewerAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.ViewerGroupBase) == 0 {
		return false
	}

	conn, err := getBindedConnection()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return false
	}
	defer conn.Close()

	req := newUserViewerSearchRequest(userDN)
	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	return err == nil && len(res.Entries) > 0
}

// Check if a user is in customer ops LDAP group
// return true if it belong to CustomerOpsGroup, false otherwise
func hasCustomerOpsAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.CustomerOpsGroupBase) == 0 {
		return false
	}

	conn, err := getBindedConnection()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return false
	}
	defer conn.Close()

	req := newCustomerOpsSearchRequest(userDN)
	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	return err == nil && len(res.Entries) > 0
}

// Check if a user is in service LDAP group
// return true if it belong to ServiceGroup, false otherwise
// Service is map to a service cluster role ( which must be deploy beside )
// Service user must be in LDAP_ADMIN_USERBASE or LDAP_USERBASE
func HasServiceAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.ServiceGroupBase) == 0 {
		log.Debug().Msgf("Using ldap groupbase %s", utils.Config.Ldap.ServiceGroupBase)
		return false
	}

	conn, err := getBindedConnection()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return false
	}
	defer conn.Close()

	req := newServiceSearchRequest(userDN)
	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	return err == nil && len(res.Entries) > 0
}

// Check if a user is in admin LDAP group
// return true if it belong to OpsGroup, false otherwise
func HasOpsAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.OpsMasterGroupBase) == 0 {
		return false
	}

	conn, err := getBindedConnection()
	if err != nil {
		utils.Log.Error().Msg(err.Error())
		return false
	}
	defer conn.Close()

	req := newUserOpsSearchRequest(userDN)
	res, err := conn.SearchWithPaging(req, utils.Config.Ldap.PageSize)

	return err == nil && len(res.Entries) > 0
}

// request to search user
func newUserSearchRequest(userBaseDN string, username string) *ldap.SearchRequest {
	userFilter := fmt.Sprintf(utils.Config.Ldap.UserFilter, username)
	return &ldap.SearchRequest{
		BaseDN:       userBaseDN,
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

// request to get user group list
func newUserAdminSearchRequest(userDN string) *ldap.SearchRequest {
	groupFilter := fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.AdminGroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       groupFilter, // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}
}

// request to get user group list
func newUserApplicationSearchRequest(userDN string) *ldap.SearchRequest {
	groupFilter := fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.AppMasterGroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       groupFilter, // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}
}

// request to get user group list
func newUserViewerSearchRequest(userDN string) *ldap.SearchRequest {
	groupFilter := fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.ViewerGroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       groupFilter, // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}
}

// request to get user group list
func newCustomerOpsSearchRequest(userDN string) *ldap.SearchRequest {
	groupFilter := fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.CustomerOpsGroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       groupFilter, // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}
}

// request to get user group list
func newServiceSearchRequest(userDN string) *ldap.SearchRequest {
	groupFilter := fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.ServiceGroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1, // limit number of entries in result, 0 values means no limitations
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       groupFilter, // filter default format : (&(objectClass=groupOfNames)(member=%s))
		Attributes:   []string{"cn"},
	}
}

// request to get user group list
func newUserOpsSearchRequest(userDN string) *ldap.SearchRequest {
	groupFilter := fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN)
	return &ldap.SearchRequest{
		BaseDN:       utils.Config.Ldap.OpsMasterGroupBase,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    1, // limit number of entries in result, 0 values means no limitations
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
