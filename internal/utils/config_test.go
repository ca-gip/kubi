package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseCustomLabels(t *testing.T) {

	t.Run("properly formatted k/v string should return two labels", func(t *testing.T) {
		result := parseCustomLabels("test=123,123=test")
		assert.Equal(t, result, map[string]string{"test": "123", "123": "test"})
	})

	t.Run("two equal without a coma should return a single label containing an equal", func(t *testing.T) {
		result := parseCustomLabels("test=123123=test")
		assert.Equal(t, result, map[string]string{"test": "123123=test"})
	})

	t.Run("two separated strings without equals should not return labels", func(t *testing.T) {
		result := parseCustomLabels("test123,123test")
		assert.Equal(t, result, map[string]string{})
	})

	t.Run("three k/v containing two illegals key should return a single label", func(t *testing.T) {
		result := parseCustomLabels("customer=ca,creator=kubi,test=123123")
		assert.Equal(t, result, map[string]string{"test": "123123"})
	})

	t.Run("a single illegal label should not return label", func(t *testing.T) {
		result := parseCustomLabels("creator=kubi")
		assert.Equal(t, result, map[string]string{})
	})

	t.Run("a single illegal label should not return label", func(t *testing.T) {
		result := parseCustomLabels("creator=kubi")
		assert.Equal(t, result, map[string]string{})
	})

	t.Run("an illegal key should not return label", func(t *testing.T) {
		result := parseCustomLabels("creator=")
		assert.Equal(t, result, map[string]string{})
	})

	t.Run("a single key should not return label", func(t *testing.T) {
		result := parseCustomLabels("test=")
		assert.Equal(t, result, map[string]string{})
	})

	t.Run("a value should not return label", func(t *testing.T) {
		result := parseCustomLabels("=test")
		assert.Equal(t, result, map[string]string{})
	})

	t.Run("a string should not return label", func(t *testing.T) {
		result := parseCustomLabels("test")
		assert.Equal(t, result, map[string]string{})
	})

}
