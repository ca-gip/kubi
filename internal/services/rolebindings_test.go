package services

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewRoleBinding(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		clusterRole string
		subjects    []v1.Subject
		expected    *v1.RoleBinding
	}{
		{
			name:        "test-rolebinding",
			namespace:   "test-namespace",
			clusterRole: "test-clusterrole",
			subjects: []v1.Subject{
				{
					Kind: "User",
					Name: "test-user",
				},
			},
			expected: &v1.RoleBinding{
				RoleRef: v1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "test-clusterrole",
				},
				Subjects: []v1.Subject{
					{
						Kind: "User",
						Name: "test-user",
					},
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rolebinding",
					Namespace: "test-namespace",
					Labels: map[string]string{
						"name":    "test-rolebinding",
						"creator": "kubi",
						"version": "v3",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := newRoleBinding(tt.name, tt.namespace, tt.clusterRole, tt.subjects)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("newRoleBinding() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
func TestToSubject(t *testing.T) {
	tests := []struct {
		DN       string
		expected string
	}{
		{
			DN:       "CN=test-user,OU=Users,DC=example,DC=com",
			expected: "test-user",
		},
		{
			DN:       "OU=Users,CN=test-user,DC=example,DC=com",
			expected: "test-user",
		},
		{
			DN:       "OU=Users,DC=example,DC=com",
			expected: "",
		},
		{
			DN:       "CN=test-user",
			expected: "test-user",
		},
		{
			DN:       "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.DN, func(t *testing.T) {
			result := toSubject(tt.DN)
			if result != tt.expected {
				t.Errorf("toSubject(%v) = %v, expected %v", tt.DN, result, tt.expected)
			}
		})
	}
}
