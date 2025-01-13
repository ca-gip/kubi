package ldap

import (
	"testing"

	"github.com/ca-gip/kubi/pkg/types"
)

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name           string
		user           *types.User
		regexpPatterns []string
		expected       bool
		expectError    bool
	}{
		{
			name: "User with project access",
			user: &types.User{
				ProjectAccesses: []string{"project1"},
			},
			regexpPatterns: []string{},
			expected:       true,
			expectError:    false,
		},
		{
			name: "Admin user",
			user: &types.User{
				IsAdmin: true,
			},
			regexpPatterns: []string{},
			expected:       true,
			expectError:    false,
		},
		{
			name: "User with matching group",
			user: &types.User{
				Groups: []string{"group1"},
			},
			regexpPatterns: []string{"GROUP1"},
			expected:       true,
			expectError:    false,
		},
		{
			name: "User with one match on multiple matchers",
			user: &types.User{
				Groups: []string{"group1"},
			},
			regexpPatterns: []string{"OTHERGROUP", "GROUP1"},
			expected:       true,
			expectError:    false,
		},
		{
			name: "User with multiple matches",
			user: &types.User{
				Groups: []string{"group1", "group2"},
			},
			regexpPatterns: []string{"GROUP2", "GROUP1"},
			expected:       true,
			expectError:    false,
		},
		{
			name: "User with no access",
			user: &types.User{
				Groups: []string{"group1"},
			},
			regexpPatterns: []string{"GROUP2"},
			expected:       false,
			expectError:    false,
		},
		{
			name: "User with invalid regex",
			user: &types.User{
				Groups: []string{"group1"},
			},
			regexpPatterns: []string{"["},
			expected:       false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := isAllowed(tt.user, tt.regexpPatterns)
			if (err != nil) != tt.expectError {
				t.Errorf("isAllowed() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if result != tt.expected {
				t.Errorf("isAllowed() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
