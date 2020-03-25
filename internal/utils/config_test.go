package utils

import (
	"k8s.io/utils/diff"
	"reflect"
	"testing"
)

// Please, one func per test for readability

func TestParseCustomLabels(t *testing.T) {
	testCases := []struct {
		given  string
		expect map[string]string
	}{
		{
			given:  "test=123,123=test",
			expect: map[string]string{"test": "123", "123": "test"},
			//description: "",

		},
		{
			given:  "test=123123=test",
			expect: map[string]string{"test": "123123=test"},
		},
		{
			given:  "test123,123test",
			expect: map[string]string{},
		},
		{
			given:  "customer=ca,creator=kubi,test=123123=test",
			expect: map[string]string{"test": "123123=test"},
		},
		{
			given:  "creator=kubi",
			expect: map[string]string{},
		},
	}

	for index, testCase := range testCases {
		result := parseCustomLabels(testCase.given)
		if !reflect.DeepEqual(testCase.expect, result) {
			t.Errorf("Test Case %d, Unexpected result\nDiff:\n %s",
				index,
				diff.ObjectGoPrintSideBySide(testCase.expect, result))
		}

	}

}

// Use more combination of failure
//given:  "customer==ca",
//given:  "cust=omer=ca",
//given:  "customer=",
//given:  "customer=,",
//given:  "=ca",
