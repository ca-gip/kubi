package services_test

import (
	"github.com/ca-gip/kubi/internal/services"
	"github.com/ca-gip/kubi/internal/utils"
	"github.com/stretchr/testify/assert"
	"regexp"
	"testing"
)

func TestEnvironmentMapping(t *testing.T) {
	t.Run("with_valid_short_name", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-dev")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-development", result.Namespace)
		assert.Equal(t, "development", result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_short_name-int", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-int")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-integration", result.Namespace)
		assert.Equal(t, "integration", result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_short_name-uat", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-uat")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-uat", result.Namespace)
		assert.Equal(t, "uat", result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_short_name-prod", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-prd")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-production", result.Namespace)
		assert.Equal(t, "production", result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_short_name-preprod", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-pprd")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-preproduction", result.Namespace)
		assert.Equal(t, utils.KubiEnvironmentPreproduction, result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_name", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-development")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-development", result.Namespace)
		assert.Equal(t, "development", result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_name-int", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-integration")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-integration", result.Namespace)
		assert.Equal(t, utils.KubiEnvironmentIntegration, result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_name-uat", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-uat")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-uat", result.Namespace)
		assert.Equal(t, utils.KubiEnvironmentUAT, result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_name-prod", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-production")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-production", result.Namespace)
		assert.Equal(t, utils.KubiEnvironmentProduction, result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_name-preproduction", func(t *testing.T) {
		result := services.EnvironmentParser("whatever-preproduction")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever-preproduction", result.Namespace)
		assert.Equal(t, utils.KubiEnvironmentPreproduction, result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})

	t.Run("with_valid_name-without-env", func(t *testing.T) {
		result := services.EnvironmentParser("whatever")
		assert.NotNil(t, result)
		assert.Equal(t, "whatever", result.Namespace)
		assert.Equal(t, utils.Empty, result.Environment)
		assert.Equal(t, "whatever", result.Project)
	})
}

func TestGetUserNamespace(t *testing.T) {
	groups := []string{
		"valid_group_admin",
		"valid_GROUP_ADMIN",
		"valid_group_with_a_lot_of_split",
		"notvalid",
	}

	t.Run("with_valid_name", func(t *testing.T) {

		result, error := services.GetUserNamespace(groups[0])

		assert.Nil(t, error)
		assert.NotNil(t, result)
		assert.Equal(t, "group", result.Namespace)
		assert.Equal(t, utils.Empty, result.Environment)
		assert.Equal(t, "admin", result.Role)

	})

	t.Run("with_uppercase_name", func(t *testing.T) {

		result, error := services.GetUserNamespace(groups[1])

		assert.Nil(t, error)
		assert.NotNil(t, result)
		assert.Equal(t, "group", result.Namespace)
		assert.Equal(t, "admin", result.Role)

	})

	t.Run("with more than 2 split", func(t *testing.T) {

		result, error := services.GetUserNamespace(groups[2])

		assert.Nil(t, error)
		assert.NotNil(t, result)
		assert.Equal(t, "split", result.Role)
		assert.Equal(t, "of", result.Namespace)

	})

	t.Run("with_missing_role", func(t *testing.T) {

		result, error := services.GetUserNamespace(groups[3])

		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("with no separator", func(t *testing.T) {

		result, error := services.GetUserNamespace("test-test")

		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("with the separator character", func(t *testing.T) {

		result, error := services.GetUserNamespace("_")

		assert.NotNil(t, error)
		assert.Nil(t, result)
	})

	t.Run("with multiple separator", func(t *testing.T) {

		result, error := services.GetUserNamespace("______")

		assert.NotNil(t, error)
		assert.Nil(t, result)
	})

	t.Run("with invalid caracter separator", func(t *testing.T) {

		result, error := services.GetUserNamespace("_$_@_!")

		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("with valid caracter but not DNS-1123 compliant", func(t *testing.T) {

		result, error := services.GetUserNamespace("_-_a-b")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("with valid caracter but not DNS-1123 compliant for namespace", func(t *testing.T) {

		result, error := services.GetUserNamespace("_-_ab")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("with valid caracter but not DNS-1123 compliant for role", func(t *testing.T) {

		result, error := services.GetUserNamespace("ok-ca-va_-ab")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("exceeded max DNS-1123 size for namespace", func(t *testing.T) {

		result, error := services.GetUserNamespace("namespacetoolongtocheckthedns1123maxlenghineedtoaddcharactertogoto63imready_admin")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("exceeded max DNS-1123 size for role", func(t *testing.T) {

		result, error := services.GetUserNamespace("demo_namespacetoolongtocheckthedns1123maxlenghineedtoaddcharactertogoto63imready")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("empty", func(t *testing.T) {

		result, error := services.GetUserNamespace("")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("empty role", func(t *testing.T) {

		result, error := services.GetUserNamespace("_test_")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("invalid regexp", func(t *testing.T) {
		goodRegexp := services.DnsParser
		services.DnsParser = regexp.MustCompile("(?:.+_+)*_(?P<role>.*)$")
		result, error := services.GetUserNamespace("")
		services.DnsParser = goodRegexp
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

	t.Run("with_valid_name_and_env", func(t *testing.T) {

		result, error := services.GetUserNamespace("DL_NATIVE-dev_ADMIN")

		assert.Nil(t, error)
		assert.NotNil(t, result)
		assert.Equal(t, "native-development", result.Namespace)
		assert.Equal(t, "development", result.Environment)
		assert.Equal(t, "admin", result.Role)

	})

	t.Run("with_valid_name_and_env_pprd", func(t *testing.T) {

		result, error := services.GetUserNamespace("DL_NATIVE-pprd_ADMIN")

		assert.Nil(t, error)
		assert.NotNil(t, result)
		assert.Equal(t, "native-preproduction", result.Namespace)
		assert.Equal(t, "preproduction", result.Environment)
		assert.Equal(t, "admin", result.Role)

	})

	t.Run("blacklisted kubi-admins clusterRoleBinding name should be protected", func(t *testing.T) {
		result, error := services.GetUserNamespace("kubi_admins")
		assert.NotNil(t, error)
		assert.Nil(t, result)

	})

}

func TestGetUserNamespaces(t *testing.T) {
	groups := []string{
		"valid_group_admin",
		"valid_GROUP_ADMIN",
		"valid_group_with_a_lot_of_split",
		"notvalid",
		"____",
		"--_--_--_",
	}

	t.Run("with only 3 valid group", func(t *testing.T) {
		result := services.GetUserNamespaces(groups)
		assert.NotNil(t, result)
		assert.Len(t, result, 3)

	})

	t.Run("with blacklisted namespaces", func(t *testing.T) {
		result := services.GetUserNamespaces([]string{
			"kube-system_admin",
			"kube-public_admin",
			"ingress-nginx_admin",
			"default_admin",
		})
		assert.NotNil(t, result)
		assert.Len(t, result, 0)

	})

}
