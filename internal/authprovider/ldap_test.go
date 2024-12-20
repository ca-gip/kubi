package ldap

import (
	"testing"

	"gopkg.in/ldap.v2"
)

func TestListGroups(t *testing.T) {
	tests := []struct {
		name     string
		members  UserMemberships
		expected []string
	}{
		{
			name: "All groups",
			members: UserMemberships{
				AdminAccess: []*ldap.Entry{
					{DN: "cn=admin1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"admin1"}}}},
					{DN: "cn=admin2", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"admin2"}}}},
				},
				AppOpsAccess: []*ldap.Entry{
					{DN: "cn=appops1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"appops1"}}}},
				},
				CustomerOpsAccess: []*ldap.Entry{
					{DN: "cn=customerops1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"customerops1"}}}},
				},
				ViewerAccess: []*ldap.Entry{
					{DN: "cn=viewer1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"viewer1"}}}},
				},
				ServiceAccess: []*ldap.Entry{
					{DN: "cn=service1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"service1"}}}},
				},
				CloudOpsAccess: []*ldap.Entry{
					{DN: "cn=cloudops1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"cloudops1"}}}},
				},
				ClusterGroupsAccess: []*ldap.Entry{
					{DN: "cn=cluster1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"cluster1"}}}},
				},
			},
			expected: []string{"admin1", "admin2", "appops1", "customerops1", "viewer1", "service1", "cloudops1", "cluster1"},
		},
		{
			name: "No groups",
			members: UserMemberships{
				AdminAccess:         []*ldap.Entry{},
				AppOpsAccess:        []*ldap.Entry{},
				CustomerOpsAccess:   []*ldap.Entry{},
				ViewerAccess:        []*ldap.Entry{},
				ServiceAccess:       []*ldap.Entry{},
				CloudOpsAccess:      []*ldap.Entry{},
				ClusterGroupsAccess: []*ldap.Entry{},
			},
			expected: []string{},
		},
		{
			name: "Some groups",
			members: UserMemberships{
				AdminAccess: []*ldap.Entry{
					{DN: "cn=admin1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"admin1"}}}},
				},
				AppOpsAccess: []*ldap.Entry{
					{DN: "cn=appops1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"appops1"}}}},
				},
				CustomerOpsAccess: []*ldap.Entry{},
				ViewerAccess: []*ldap.Entry{
					{DN: "cn=viewer1", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"viewer1"}}}},
				},
				ServiceAccess:       []*ldap.Entry{},
				CloudOpsAccess:      []*ldap.Entry{},
				ClusterGroupsAccess: []*ldap.Entry{},
			},
			expected: []string{"admin1", "appops1", "viewer1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.members.ListGroups()
			if len(got) != len(tt.expected) {
				t.Errorf("ListGroups() = %v, want %v", got, tt.expected)
			}
			for i, group := range got {
				if group != tt.expected[i] {
					t.Errorf("ListGroups() = %v, want %v", got, tt.expected)
				}
			}
		})
	}
}
