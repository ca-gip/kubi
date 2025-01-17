package utils

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestInitLogger(t *testing.T) {
	// Capture the output of the logger
	var buf bytes.Buffer

	// Initialize the logger
	InitLogger(&buf)

	// Log a test message
	slog.Debug("test message")

	// Check if the output contains the expected log entry
	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("test message")) {
		t.Errorf("expected log entry to contain 'test message', got %s", output)
	}
}
