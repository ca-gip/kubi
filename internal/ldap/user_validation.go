package ldap

import (
	"fmt"

	"github.com/ca-gip/kubi/pkg/types"
	"gopkg.in/ldap.v2"
)

// Finds an user and check if its password is correct.
func (c *LDAPClient) validateUserCredentials(base string, username string, password string) (*types.User, error) {
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, fmt.Sprintf(c.UserFilter, username), []string{"dn", "mail"}, nil)

	conn, err := c.ldapConnectAndBind(c.BindDN, c.BindPassword)
	if err != nil {
		return &types.User{}, err
	}
	defer conn.Close()

	res, err := conn.SearchWithPaging(req, c.PageSize)

	switch {
	case err != nil:
		return &types.User{}, fmt.Errorf("error searching for user %s, %w", username, err)
	case len(res.Entries) == 0:
		return &types.User{}, fmt.Errorf("no result for the user search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		return &types.User{}, fmt.Errorf("multiple entries found for the user search filter '%s'", req.Filter)
	}

	userDN := res.Entries[0].DN
	mail := res.Entries[0].GetAttributeValue("mail")
	user := &types.User{
		Username: username,
		UserDN:   userDN,
		Email:    mail,
	}

	_, err = c.ldapConnectAndBind(userDN, password)
	if err != nil {
		return &types.User{}, fmt.Errorf("cannot authenticate user %s in LDAP", username)
	}
	return user, nil
}
