package utils

import (
	"io"
	"log/slog"
	"os"
)

// InitLogger initializes the logger with the given output writer, recording logs as json with rfc3339 timestamps (at the specified level).
func InitLogger(writer io.Writer, logLevel slog.Level) {
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	handler := slog.NewJSONHandler(writer, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func GetLogLevelFromEnv(defaultLevel slog.Level) slog.Level {
	logLevel := defaultLevel
	logLevel.UnmarshalText([]byte(os.Getenv("LOG_LEVEL")))
	return logLevel
}
