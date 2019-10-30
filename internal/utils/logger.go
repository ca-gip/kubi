package utils

import (
	"github.com/rs/zerolog"
	"os"
	"time"
)

var errorLogger = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
var consoleLogger = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}

var LogErr = zerolog.New(errorLogger).With().Timestamp().Logger()
var LogOther = zerolog.New(consoleLogger).With().Timestamp().Logger()

var Log = LogWrapper{
	Info:  LogOther.Info,
	Warn:  LogOther.Warn,
	Debug: LogOther.Debug,
	Error: LogErr.Error,
	Fatal: LogErr.Fatal,
}

type LogWrapper struct {
	Error func() *zerolog.Event
	Info  func() *zerolog.Event
	Warn  func() *zerolog.Event
	Debug func() *zerolog.Event
	Fatal func() *zerolog.Event
}
