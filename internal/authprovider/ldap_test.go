package ldap

import (
	"strings"
	"testing"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNewUserSearchRequest(t *testing.T) {
	t.Run("escape out special character from username input", func(t *testing.T) {
		utils.Config = &types.Config{
			Ldap: types.LdapConfig{
				UserFilter: "(cn=%s)",
			},
		}
		username := `)foo()*|&bar`

		expected := `(cn=foobar)`

		req := newUserSearchRequest("baseDN", username)
		assert.Equal(t, expected, req.Filter)
	})
}

func FuzzNewUserSearchRequest(f *testing.F) {
	utils.Config = &types.Config{
		Ldap: types.LdapConfig{
			UserFilter: "%s",
		},
	}
	specials := []string{"(", ")", "&", "*", "|"}

	for _, s := range specials {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		req := newUserSearchRequest("baseDN", s)
		assert.False(t, strings.ContainsAny(req.Filter, "()*&|"))
	})
}
