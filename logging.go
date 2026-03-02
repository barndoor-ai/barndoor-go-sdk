package barndoor

import (
	"fmt"
	"log"
)

// Logger defines the interface for SDK logging.
type Logger interface {
	Debug(message string, args ...any)
	Info(message string, args ...any)
	Warn(message string, args ...any)
	Error(message string, args ...any)
}

// defaultLogger logs to the standard log package.
type defaultLogger struct{}

func (l *defaultLogger) Debug(message string, args ...any) {
	if len(args) > 0 {
		log.Printf("[DEBUG] %s %v", message, fmt.Sprint(args...))
	} else {
		log.Printf("[DEBUG] %s", message)
	}
}

func (l *defaultLogger) Info(message string, args ...any) {
	if len(args) > 0 {
		log.Printf("[INFO] %s %v", message, fmt.Sprint(args...))
	} else {
		log.Printf("[INFO] %s", message)
	}
}

func (l *defaultLogger) Warn(message string, args ...any) {
	if len(args) > 0 {
		log.Printf("[WARN] %s %v", message, fmt.Sprint(args...))
	} else {
		log.Printf("[WARN] %s", message)
	}
}

func (l *defaultLogger) Error(message string, args ...any) {
	if len(args) > 0 {
		log.Printf("[ERROR] %s %v", message, fmt.Sprint(args...))
	} else {
		log.Printf("[ERROR] %s", message)
	}
}

var globalLogger Logger = &defaultLogger{}

// SetLogger sets a custom logger for the entire SDK.
func SetLogger(logger Logger) {
	globalLogger = logger
}

// GetLogger returns the current logger instance.
func GetLogger() Logger {
	return globalLogger
}

// scopedLogger wraps a logger with a scope prefix.
type scopedLogger struct {
	scope  string
	logger Logger
}

func (l *scopedLogger) Debug(message string, args ...any) {
	l.logger.Debug(fmt.Sprintf("[%s] %s", l.scope, message), args...)
}

func (l *scopedLogger) Info(message string, args ...any) {
	l.logger.Info(fmt.Sprintf("[%s] %s", l.scope, message), args...)
}

func (l *scopedLogger) Warn(message string, args ...any) {
	l.logger.Warn(fmt.Sprintf("[%s] %s", l.scope, message), args...)
}

func (l *scopedLogger) Error(message string, args ...any) {
	l.logger.Error(fmt.Sprintf("[%s] %s", l.scope, message), args...)
}

// createScopedLogger creates a logger with a scope prefix.
func createScopedLogger(scope string) Logger {
	return &scopedLogger{scope: scope, logger: globalLogger}
}
