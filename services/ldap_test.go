package services_test

import (
	"github.com/ca-gip/kubi/services"
	"github.com/stretchr/testify/assert"
	"regexp"
	"testing"
)

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
