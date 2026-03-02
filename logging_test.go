package barndoor

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// defaultLogger
// ---------------------------------------------------------------------------

func TestDefaultLogger_Debug(t *testing.T) {
	l := &defaultLogger{}
	// Should not panic
	l.Debug("test message")
	l.Debug("test message", "arg1", "arg2")
}

func TestDefaultLogger_Info(t *testing.T) {
	l := &defaultLogger{}
	l.Info("test message")
	l.Info("test message", "arg1")
}

func TestDefaultLogger_Warn(t *testing.T) {
	l := &defaultLogger{}
	l.Warn("test message")
	l.Warn("test message", "arg1")
}

func TestDefaultLogger_Error(t *testing.T) {
	l := &defaultLogger{}
	l.Error("test message")
	l.Error("test message", "arg1")
}

// ---------------------------------------------------------------------------
// SetLogger / GetLogger
// ---------------------------------------------------------------------------

func TestSetGetLogger(t *testing.T) {
	orig := GetLogger()
	defer SetLogger(orig)

	custom := &captureLogger{fn: func(string) {}}
	SetLogger(custom)

	if GetLogger() != custom {
		t.Error("GetLogger should return the custom logger set by SetLogger")
	}
}

// ---------------------------------------------------------------------------
// scopedLogger
// ---------------------------------------------------------------------------

func TestScopedLogger_Debug(t *testing.T) {
	var captured string
	orig := GetLogger()
	defer SetLogger(orig)

	SetLogger(&captureLogger{fn: func(msg string) { captured = msg }})
	logger := createScopedLogger("myScope")
	logger.Debug("hello")

	if !strings.Contains(captured, "[myScope]") {
		t.Errorf("expected scope prefix in message, got: %q", captured)
	}
	if !strings.Contains(captured, "hello") {
		t.Errorf("expected message content, got: %q", captured)
	}
}

func TestScopedLogger_Info(t *testing.T) {
	var captured string
	orig := GetLogger()
	defer SetLogger(orig)

	SetLogger(&captureLogger{fn: func(msg string) { captured = msg }})
	logger := createScopedLogger("scope")
	logger.Info("info msg")

	if !strings.Contains(captured, "[scope]") || !strings.Contains(captured, "info msg") {
		t.Errorf("unexpected message: %q", captured)
	}
}

func TestScopedLogger_Warn(t *testing.T) {
	var captured string
	orig := GetLogger()
	defer SetLogger(orig)

	SetLogger(&captureLogger{fn: func(msg string) { captured = msg }})
	logger := createScopedLogger("scope")
	logger.Warn("warn msg")

	if !strings.Contains(captured, "[scope]") || !strings.Contains(captured, "warn msg") {
		t.Errorf("unexpected message: %q", captured)
	}
}

func TestScopedLogger_Error(t *testing.T) {
	var captured string
	orig := GetLogger()
	defer SetLogger(orig)

	SetLogger(&captureLogger{fn: func(msg string) { captured = msg }})
	logger := createScopedLogger("scope")
	logger.Error("error msg")

	if !strings.Contains(captured, "[scope]") || !strings.Contains(captured, "error msg") {
		t.Errorf("unexpected message: %q", captured)
	}
}
