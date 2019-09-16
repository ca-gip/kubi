package utils

import "strings"

// Test if a string a one of suffixes array present.
func HasSuffixes(word string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(word, "-"+suffix) {
			return true
		}
	}
	return false
}

// Remove suffix if exists in array.
func TrimSuffixes(word string, suffixes []string) string {
	for _, suffix := range suffixes {
		if strings.HasSuffix(word, suffix) {
			return strings.TrimSuffix(word, "-"+suffix)
		}
	}
	return word
}
