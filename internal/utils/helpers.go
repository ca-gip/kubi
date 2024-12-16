package utils

import (
	"os"
	"strings"
)

func IsEmpty(value string) bool {
	return len(value) == 0
}

// Print error and exit if error occurred
func Check(e error) {
	if e != nil {
		Log.Error().Msg(e.Error())
	}
}

func Checkf(e error, msg string) {
	if e != nil {
		Log.Error().Msgf("%v : %v", msg, e)
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func AppendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

func Union(a map[string]string, b map[string]string) map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func IsInPrivilegedNsList(namespace string) bool {
	for _, nsItem := range Config.PrivilegedNamespaces {
		if strings.Contains(nsItem, namespace) {
			return true
		}
	}
	return false
}
