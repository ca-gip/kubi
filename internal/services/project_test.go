package services

import (
	"fmt"
	"testing"

	"github.com/ca-gip/kubi/internal/utils"
	"github.com/ca-gip/kubi/pkg/types"
)

func TestNamespaceParser(t *testing.T) {
	tests := []struct {
		name                       string
		input                      string
		expectedProjectName        string
		expectedProjectEnvironment string
	}{
		{"with_valid_short_name", "whatever-dev", "whatever", "development"},
		{"with_valid_short_name-int", "whatever-int", "whatever", "integration"},
		{"with_valid_short_name-uat", "whatever-uat", "whatever", "uat"},
		{"with_valid_short_name-preprod", "whatever-pprd", "whatever", "preproduction"},
		{"with_valid_short_name-prod", "whatever-prd", "whatever", "production"},
		{"with_valid_name", "whatever-development", "whatever", "development"},
		{"with_valid_name-int", "whatever-integration", "whatever", "integration"},
		{"with_valid_name-uat", "whatever-uat", "whatever", "uat"},
		{"with_valid_name-preproduction", "whatever-preproduction", "whatever", "preproduction"},
		{"with_valid_name-prod", "whatever-production", "whatever", "production"},
		{"with_valid_name-without-env", "whatever", "whatever", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultProjectName, resultEnvironmentName := namespaceParser(tt.input)
			if tt.expectedProjectName != resultProjectName {
				t.Errorf("expected %s, got %s", tt.expectedProjectName, resultProjectName)
			}
			if tt.expectedProjectEnvironment != resultEnvironmentName {
				t.Errorf("expected %s, got %s", tt.expectedProjectEnvironment, resultEnvironmentName)
			}
		})
	}
}

func TestNewProject(t *testing.T) {
	tests := []struct {
		name          string
		group         string
		expectedError string
		expectedProj  *types.Project
	}{
		{
			name:  "valid_group_with_environment",
			group: "DL_NATIVE-dev_ADMIN",
			expectedProj: &types.Project{
				Project:     "native",
				Role:        "admin",
				Source:      "DL_NATIVE-dev_ADMIN",
				Environment: "development",
			},
		},
		{
			name:  "valid_group_without_environment",
			group: "DL_NATIVE_ADMIN",
			expectedProj: &types.Project{
				Project:     "native",
				Role:        "admin",
				Source:      "DL_NATIVE_ADMIN",
				Environment: "",
			},
		},
		{
			name:  "complex_valid_group_with_environment",
			group: "DL_KUB_CATS_NATIVE-dev_ADMIN",
			expectedProj: &types.Project{
				Project:     "native",
				Role:        "admin",
				Source:      "DL_NATIVE-dev_ADMIN",
				Environment: "development",
			},
		},
		{
			name:  "complex_valid_group_without_environment",
			group: "DL_KUB_CATS_NATIVE_ADMIN",
			expectedProj: &types.Project{
				Project:     "native",
				Role:        "admin",
				Source:      "DL_NATIVE_ADMIN",
				Environment: "",
			},
		},
		{
			name:          "no_separator",
			group:         "test-test",
			expectedError: "cannot find a namespace and a role - the group 'test-test' cannot be parsed",
		},
		{
			name:          "empty_group",
			group:         "",
			expectedError: "cannot find a namespace and a role - the group '' cannot be parsed",
		},
		{
			name:          "only_a_single_separator",
			group:         "_",
			expectedError: "cannot find a namespace and a role - the group '_' cannot be parsed",
		},
		{
			// In this case the role and the namespace are '_'
			name:          "only_separators",
			group:         "___",
			expectedError: "the project from group ___ cannot be created, its namespace _ is not dns1123 compliant",
		},
		{
			name:          "invalid_chars_as_namespace",
			group:         "_$_@_!_ADMIN",
			expectedError: "the project from group _$_@_!_ADMIN cannot be created, its namespace ! is not dns1123 compliant",
		},
		{
			name:          "blacklisted_namespace",
			group:         "kube-system_ADMIN",
			expectedError: "the project from group kube-system_ADMIN cannot be created, its namespace kube-system is protected through blacklist",
		},
		{
			name:          "invalid_role",
			group:         "DL_NATIVE_invalidrole",
			expectedError: "the project from group DL_NATIVE_invalidrole cannot be created, its role invalidrole is not valid",
		},
		{
			name:          "invalid_role",
			group:         "DL_NATIVE",
			expectedError: "the project from group DL_NATIVE cannot be created, its role native is not valid",
		},
		{
			name:          "namespace_exceeds_max_length",
			group:         "thisisaveryveryveryverylongnamespacethatexceedsthemaxallowedlength_ADMIN",
			expectedError: fmt.Sprintf("the name for namespace cannot exceeded %v characters", utils.DNS1123LabelMaxLength),
		},
		{
			name:          "role_exceeds_max_length",
			group:         "DL_NATIVE_thisisaveryveryveryveryveryverylongrolethatexceedsthemaxallowedlength",
			expectedError: fmt.Sprintf("the name for role cannot exceeded %v characters", utils.DNS1123LabelMaxLength),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project, err := NewProject(tt.group)
			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if err.Error() != tt.expectedError {
					t.Errorf("expected error:\n%s\ngot:\n%s\n", tt.expectedError, err.Error())
				}
				if project != nil {
					t.Errorf("expected project to be nil, but got %v", project)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got %v", err)
				}
				if project == nil {
					t.Errorf("expected project, but got nil")
				} else {
					if project.Project != tt.expectedProj.Project {
						t.Errorf("expected project:\n%s\ngot:\n%s", tt.expectedProj.Project, project.Project)
					}
					if project.Role != tt.expectedProj.Role {
						t.Errorf("expected role:\n%s\ngot:\n%s", tt.expectedProj.Role, project.Role)
					}
					if project.Environment != tt.expectedProj.Environment {
						t.Errorf("expected environment:\n%s\ngot:\n%s", tt.expectedProj.Environment, project.Environment)
					}
				}
			}
		})
	}
}
