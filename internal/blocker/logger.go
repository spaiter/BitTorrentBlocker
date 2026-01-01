package blocker

import (
	"log"
)

// LogLevel represents logging verbosity
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// Logger wraps standard log with level support
type Logger struct {
	level LogLevel
}

// NewLogger creates a logger with the specified level
func NewLogger(levelStr string) *Logger {
	var level LogLevel
	switch levelStr {
	case "error":
		level = LogLevelError
	case "warn":
		level = LogLevelWarn
	case "info":
		level = LogLevelInfo
	case "debug":
		level = LogLevelDebug
	default:
		level = LogLevelInfo
	}
	return &Logger{level: level}
}

func (l *Logger) Error(format string, v ...interface{}) {
	if l.level >= LogLevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}

func (l *Logger) Warn(format string, v ...interface{}) {
	if l.level >= LogLevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	if l.level >= LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level >= LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}
