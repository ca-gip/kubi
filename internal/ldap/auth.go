package ldap

import (
	"fmt"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"gopkg.in/ldap.v2"
)

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
