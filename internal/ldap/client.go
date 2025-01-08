package ldap

import (
	"fmt"

	"github.com/ca-gip/kubi/internal/project"
	"github.com/ca-gip/kubi/pkg/types"
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

// Authenticate a user through LDAP or LDS
// return if bind was ok, the userDN for next usage, and error if occurred
func (c *LDAPClient) AuthN(username string, password string) (*types.User, error) {

	user := &types.User{}
	// Get User Distinguished Name for Standard User
	user, err := c.validateUserCredentials(c.UserBase, username, password)
	if err == nil {
		return user, nil
	}

	// Now handling errors to get standard user, falling back to admin user, if
	// config allows it
	if len(c.AdminUserBase) <= 0 {
		return &types.User{}, fmt.Errorf("cannot find user %s in LDAP", username)
	}

	// Retry as admin
	user, err = c.validateUserCredentials(c.AdminUserBase, username, password)
	if err != nil {
		return &types.User{}, fmt.Errorf("cannot find admin user %s in LDAP", username)
	}

	return user, nil
}

func (c *LDAPClient) AuthZ(user *types.User) (*types.User, error) {
	// Get User Memberships
	if user == nil {
		return &types.User{}, fmt.Errorf("cannot get memberships for nil user")
	}
	if user.Email == "" || user.UserDN == "" || user.Username == "" {
		return &types.User{}, fmt.Errorf("cannot get memberships for empty user %v in LDAP", user)
	}

	// to keep for historical reasons: We continue to issue tokens with old data until
	// ArgoCD + promote + other? is updated to use the new groups.
	// When migration is over, we can simplify the User struct and remove the old fields.

	ldapMemberships, err := c.getMemberships(user.UserDN)
	if err != nil {
		return &types.User{}, fmt.Errorf("cannot get memberships for user %s in LDAP", user.Username)
	}

	user.Groups = ldapMemberships.toGroupNames()

	user.IsAdmin = len(ldapMemberships.AdminAccess) > 0
	user.IsAppOps = (len(ldapMemberships.AppOpsAccess) > 0) || (len(ldapMemberships.CustomerOpsAccess) > 0)
	user.IsCloudOps = len(ldapMemberships.CloudOpsAccess) > 0
	user.IsViewer = len(ldapMemberships.ViewerAccess) > 0
	user.IsService = len(ldapMemberships.ServiceAccess) > 0

	user.ProjectAccesses = ldapMemberships.toProjectNames()

	return user, nil
}

// ListProjects Implement ProjectLister interface to be able to replace with a list of projects for testing.
func (c *LDAPClient) ListProjects() ([]*types.Project, error) {
	allClusterGroups, err := c.getProjectGroups()
	if err != nil {
		return nil, err
	}
	if len(allClusterGroups) == 0 {
		return nil, fmt.Errorf("no ldap groups found")
	}
	return project.GetProjectsFromGrouplist(allClusterGroups), nil
}
