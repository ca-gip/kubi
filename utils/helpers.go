package utils

import "os"

func IsEmpty(value string) bool {
	return len(value) == 0
}

// Print error and exit if error occured
func check(e error) {
	if e != nil {
		Log.Error().Err(e)
	}
}

func checkf(e error, msg string) {
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
