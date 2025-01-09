package services

import (
	"testing"
)

func TestAppendIfMissing(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		element  string
		expected []string
	}{
		{
			name:     "Element is missing",
			slice:    []string{"a", "b", "c"},
			element:  "d",
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "Element is present",
			slice:    []string{"a", "b", "c"},
			element:  "b",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Empty slice",
			slice:    []string{},
			element:  "a",
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendIfMissing(tt.slice, tt.element)
			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, result)
					break
				}
			}
		})
	}
}
