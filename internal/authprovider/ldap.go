package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"gopkg.in/ldap.v2"
)

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

// Authenticate a user through LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occurred
func GetUserGroups(userDN string) ([]string, error) {

	// This is better than binding directly to the userDN and querying memberOf:
	// in case of nested groups or other complex group structures, the memberOf
	// attribute may not be populated correctly.
	req := ldap.NewSearchRequest(
		utils.Config.Ldap.GroupBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)
	results, err := ldapQuery(*req)
	if err != nil {
		return nil, fmt.Errorf("error searching base %v with filter %v due to %w", req.BaseDN, req.Filter, err)
	}

	// TODO: REMOVE THIS, ONLY DEBUGGING PURPOSES
	utils.Log.Debug().Msg(fmt.Sprintf("User %s is in groups %v", userDN, results.Entries))

	var groups []string
	for _, entry := range results.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}

// Authenticate a user through LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occurred
func GetAllGroups() ([]string, error) {

	request := newGroupSearchRequest()
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
	conn, err := ldapConnectAndBind(utils.Config.Ldap.BindDN, utils.Config.Ldap.BindPassword)
	if err != nil {
		return types.User{}, err
	}
	defer conn.Close()

	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, fmt.Sprintf(utils.Config.Ldap.UserFilter, username), []string{"dn", "mail"}, nil)
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

// Check if a user is in admin LDAP group
// return true if it belong to AdminGroup, false otherwise (including errors or misconfiguration)
// TODO: Work on the Has* functions - use composition?
func HasAdminAccess(userDN string) bool {

	// No need to go further, there is no Admin Group Base
	if len(utils.Config.Ldap.AdminGroupBase) == 0 {
		return false
	}
	req := ldap.NewSearchRequest(
		utils.Config.Ldap.AdminGroupBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)

	res, err := ldapQuery(*req)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("issue querying for admin access %v", err.Error()))
		return false
	}

	return len(res.Entries) > 0
}

// Return true if the user manage application at cluster wide scope
func HasApplicationAccess(userDN string) bool {
	return hasApplicationAccess(userDN) || hasCustomerOpsAccess(userDN)
}

// Check if a user is in application LDAP group
// return true if it belong to ApplicationGroup, false otherwise (including errors or misconfiguration)
func hasApplicationAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.AppMasterGroupBase) == 0 {
		return false
	}

	req := ldap.NewSearchRequest(
		utils.Config.Ldap.AppMasterGroupBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)

	res, err := ldapQuery(*req)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("issue querying for application access %v", err.Error()))
		return false
	}

	return len(res.Entries) > 0
}

// Check if a user is in customer ops LDAP group
// return true if it belong to CustomerOpsGroup, false otherwise (including errors or misconfiguration)
func hasCustomerOpsAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.CustomerOpsGroupBase) == 0 {
		return false
	}

	req := ldap.NewSearchRequest(
		utils.Config.Ldap.CustomerOpsGroupBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)

	res, err := ldapQuery(*req)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("issue querying for customer ops access %v", err.Error()))
		return false
	}

	return len(res.Entries) > 0
}

// Check if a user is in viewer LDAP group
// return true if it belong to viewerGroup, false otherwise (including errors or misconfiguration)
func HasViewerAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.ViewerGroupBase) == 0 {
		return false
	}
	req := ldap.NewSearchRequest(
		utils.Config.Ldap.ViewerGroupBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)
	res, err := ldapQuery(*req)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("issue querying for viewer access %v", err.Error()))
		return false
	}

	return len(res.Entries) > 0
}

// Check if a user is in service LDAP group
// return true if it belong to ServiceGroup, false otherwise (including errors or misconfiguration)
// Service is map to a service cluster role ( which must be deploy beside ) # ?!? I don't understand this comment
// Service user must be in LDAP_ADMIN_USERBASE or LDAP_USERBASE
func HasServiceAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.ServiceGroupBase) == 0 {
		log.Debug().Msgf("Using ldap groupbase %s", utils.Config.Ldap.ServiceGroupBase)
		return false
	}

	req := ldap.NewSearchRequest(
		utils.Config.Ldap.ServiceGroupBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)

	res, err := ldapQuery(*req)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("issue querying for service access %v", err.Error()))
		return false
	}

	return len(res.Entries) > 0
}

// Check if a user is in cloudops LDAP group
// return true if it belong to OpsGroup, false otherwise (including errors or misconfiguration)
func HasOpsAccess(userDN string) bool {

	// No need to go further, there is no Application Group Base
	if len(utils.Config.Ldap.OpsMasterGroupBase) == 0 {
		return false
	}

	req := ldap.NewSearchRequest(
		utils.Config.Ldap.OpsMasterGroupBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false,
		fmt.Sprintf("(&(|(objectClass=groupOfNames)(objectClass=group))(member=%s))", userDN),
		[]string{"cn"},
		nil,
	)

	res, err := ldapQuery(*req)
	if err != nil {
		utils.Log.Error().Msg(fmt.Sprintf("issue querying for ops access %v", err.Error()))
		return false
	}

	return len(res.Entries) > 0
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
