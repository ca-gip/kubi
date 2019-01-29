package services

import (
	"errors"
	"fmt"
	"github.com/ca-gip/kubi/types"
	"github.com/ca-gip/kubi/utils"
	"regexp"
	"strings"
)

var DnsParser = regexp.MustCompile("(?:.+_+)*(?P<namespace>.+)_(?P<role>.+)$")

// Get Namespace, Role for a list of group name
func GetUserNamespaces(groups []string) []*types.AuthJWTTupple {
	res := make([]*types.AuthJWTTupple, 0)
	for _, groupname := range groups {
		tupple, err := GetUserNamespace(groupname)
		if err == nil {
			res = append(res, tupple)
		} else {
			utils.Log.Error().Msg(err.Error())
		}
	}
	return res
}

// Get Namespace, Role for a group name
func GetUserNamespace(group string) (*types.AuthJWTTupple, error) {

	lowerGroup := strings.ToLower(group)
	keys := DnsParser.SubexpNames()
	if len(keys) < 3 {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group parser doesn't have the two mandatory key: namespace and role,
			you have only this: %v")
			 `, keys))
	}

	countSplits := len(DnsParser.FindStringSubmatch(lowerGroup))

	if countSplits != 3 {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group '%v', cannot be parse. Can't find a namespace and a role'
			 `, group))
	}

	//lowerGroup = strings.TrimPrefix(lowerGroup, )
	namespace, role := DnsParser.ReplaceAllString(lowerGroup, "${namespace}"), DnsParser.ReplaceAllString(lowerGroup, "${role}")

	isNamespaceValid, _ := regexp.MatchString(utils.Dns1123LabelFmt, namespace)
	isRoleValid, _ := regexp.MatchString(utils.Dns1123LabelFmt, role)

	if utils.Index(utils.BlacklistedNamespaces, namespace) != -1 {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group %v, cannot be created. 
			The namespace %v is protected.`, group, namespace))
	} else if !isNamespaceValid {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group %v, cannot be created. 
			The namespace %v is not dns1123 compliant.`, group, namespace))
	} else if !isRoleValid {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The ldap group %v, cannot be created. 
			The role %v is not dns1123 compliant.`, group, namespace))
	} else if len(namespace) > utils.DNS1123LabelMaxLength {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The name for namespace cannot exceeded %v characters.`, utils.DNS1123LabelMaxLength))
	} else if len(role) > utils.DNS1123LabelMaxLength {
		return nil, errors.New(fmt.Sprintf(`
			LDAP: The name for role cannot exceeded %v characters.`, utils.DNS1123LabelMaxLength))
	} else {
		return &types.AuthJWTTupple{
			Namespace: namespace,
			Role:      role,
		}, nil
	}
}
