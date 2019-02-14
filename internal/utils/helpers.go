package utils

import "os"

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

func hasEnv(key string) bool {
	_, ok := os.LookupEnv(key)
	return ok
}

func AppendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}
