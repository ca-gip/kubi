package utils

import "strings"

// Test if a string a one of suffixes array present.
func HasSuffixes(word string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(word, suffix) {
			return true
		}
	}
	return false
}
