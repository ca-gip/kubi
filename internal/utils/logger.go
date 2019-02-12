package utils

import (
	"github.com/rs/zerolog"
	"os"
	"time"
)

var output = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}

var Log = zerolog.New(output).With().Timestamp().Logger()
