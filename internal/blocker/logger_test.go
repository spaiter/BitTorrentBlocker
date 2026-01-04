package blocker

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name     string
		levelStr string
		want     LogLevel
	}{
		{"Error level", "error", LogLevelError},
		{"Warn level", "warn", LogLevelWarn},
		{"Info level", "info", LogLevelInfo},
		{"Debug level", "debug", LogLevelDebug},
		{"Default (invalid)", "invalid", LogLevelInfo},
		{"Default (empty)", "", LogLevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.levelStr)
			if logger.level != tt.want {
				t.Errorf("NewLogger(%q).level = %v, want %v", tt.levelStr, logger.level, tt.want)
			}
		})
	}
}

func TestLoggerLevels(t *testing.T) {
	tests := []struct {
		name          string
		loggerLevel   string
		testFunc      func(*Logger)
		shouldLog     bool
		expectedLevel string
	}{
		// Error logs
		{
			name:          "Error logs at error level",
			loggerLevel:   "error",
			testFunc:      func(l *Logger) { l.Error("test error") },
			shouldLog:     true,
			expectedLevel: "[ERROR]",
		},
		{
			name:          "Error logs at warn level",
			loggerLevel:   "warn",
			testFunc:      func(l *Logger) { l.Error("test error") },
			shouldLog:     true,
			expectedLevel: "[ERROR]",
		},
		{
			name:          "Error logs at info level",
			loggerLevel:   "info",
			testFunc:      func(l *Logger) { l.Error("test error") },
			shouldLog:     true,
			expectedLevel: "[ERROR]",
		},
		{
			name:          "Error logs at debug level",
			loggerLevel:   "debug",
			testFunc:      func(l *Logger) { l.Error("test error") },
			shouldLog:     true,
			expectedLevel: "[ERROR]",
		},

		// Warn logs
		{
			name:          "Warn doesn't log at error level",
			loggerLevel:   "error",
			testFunc:      func(l *Logger) { l.Warn("test warning") },
			shouldLog:     false,
			expectedLevel: "",
		},
		{
			name:          "Warn logs at warn level",
			loggerLevel:   "warn",
			testFunc:      func(l *Logger) { l.Warn("test warning") },
			shouldLog:     true,
			expectedLevel: "[WARN]",
		},
		{
			name:          "Warn logs at info level",
			loggerLevel:   "info",
			testFunc:      func(l *Logger) { l.Warn("test warning") },
			shouldLog:     true,
			expectedLevel: "[WARN]",
		},

		// Info logs
		{
			name:          "Info doesn't log at error level",
			loggerLevel:   "error",
			testFunc:      func(l *Logger) { l.Info("test info") },
			shouldLog:     false,
			expectedLevel: "",
		},
		{
			name:          "Info doesn't log at warn level",
			loggerLevel:   "warn",
			testFunc:      func(l *Logger) { l.Info("test info") },
			shouldLog:     false,
			expectedLevel: "",
		},
		{
			name:          "Info logs at info level",
			loggerLevel:   "info",
			testFunc:      func(l *Logger) { l.Info("test info") },
			shouldLog:     true,
			expectedLevel: "[INFO]",
		},
		{
			name:          "Info logs at debug level",
			loggerLevel:   "debug",
			testFunc:      func(l *Logger) { l.Info("test info") },
			shouldLog:     true,
			expectedLevel: "[INFO]",
		},

		// Debug logs
		{
			name:          "Debug doesn't log at error level",
			loggerLevel:   "error",
			testFunc:      func(l *Logger) { l.Debug("test debug") },
			shouldLog:     false,
			expectedLevel: "",
		},
		{
			name:          "Debug doesn't log at warn level",
			loggerLevel:   "warn",
			testFunc:      func(l *Logger) { l.Debug("test debug") },
			shouldLog:     false,
			expectedLevel: "",
		},
		{
			name:          "Debug doesn't log at info level",
			loggerLevel:   "info",
			testFunc:      func(l *Logger) { l.Debug("test debug") },
			shouldLog:     false,
			expectedLevel: "",
		},
		{
			name:          "Debug logs at debug level",
			loggerLevel:   "debug",
			testFunc:      func(l *Logger) { l.Debug("test debug") },
			shouldLog:     true,
			expectedLevel: "[DEBUG]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer log.SetOutput(nil)

			logger := NewLogger(tt.loggerLevel)
			tt.testFunc(logger)

			output := buf.String()
			if tt.shouldLog {
				if output == "" {
					t.Errorf("Expected log output but got none")
				}
				if !strings.Contains(output, tt.expectedLevel) {
					t.Errorf("Expected log to contain %q, got: %q", tt.expectedLevel, output)
				}
			} else if output != "" {
				t.Errorf("Expected no log output but got: %q", output)
			}
		})
	}
}

func TestLoggerFormatting(t *testing.T) {
	tests := []struct {
		name         string
		logFunc      func(*Logger)
		expectedText string
	}{
		{
			name: "Error with formatting",
			logFunc: func(l *Logger) {
				l.Error("error code %d: %s", 404, "not found")
			},
			expectedText: "error code 404: not found",
		},
		{
			name: "Warn with formatting",
			logFunc: func(l *Logger) {
				l.Warn("warning: %s", "low disk space")
			},
			expectedText: "warning: low disk space",
		},
		{
			name: "Info with formatting",
			logFunc: func(l *Logger) {
				l.Info("server started on port %d", 8080)
			},
			expectedText: "server started on port 8080",
		},
		{
			name: "Debug with formatting",
			logFunc: func(l *Logger) {
				l.Debug("processing %d items", 100)
			},
			expectedText: "processing 100 items",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer log.SetOutput(nil)

			logger := NewLogger("debug")
			tt.logFunc(logger)

			output := buf.String()
			if !strings.Contains(output, tt.expectedText) {
				t.Errorf("Expected log to contain %q, got: %q", tt.expectedText, output)
			}
		})
	}
}
