package utils

import (
	"io"
	"log/slog"
)

// InitLogger initializes the logger with the given output writer, recording logs as json with rfc3339 timestamps (at debug level).
func InitLogger(writer io.Writer) {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	handler := slog.NewJSONHandler(writer, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
