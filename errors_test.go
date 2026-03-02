package barndoor

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// BarndoorError
// ---------------------------------------------------------------------------

func TestBarndoorError_Error(t *testing.T) {
	err := &BarndoorError{Message: "test error"}
	if err.Error() != "test error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test error")
	}
}

// ---------------------------------------------------------------------------
// NewTokenError
// ---------------------------------------------------------------------------

func TestNewTokenError_WithHelpText(t *testing.T) {
	err := NewTokenError("Token expired", "Try re-authenticating.")
	if !strings.Contains(err.Error(), "Token expired") {
		t.Errorf("error should contain message: %v", err)
	}
	if !strings.Contains(err.Error(), "Try re-authenticating.") {
		t.Errorf("error should contain help text: %v", err)
	}
	if err.HelpText != "Try re-authenticating." {
		t.Errorf("HelpText = %q, want %q", err.HelpText, "Try re-authenticating.")
	}
}

func TestNewTokenError_WithoutHelpText(t *testing.T) {
	err := NewTokenError("Token expired", "")
	if !strings.Contains(err.Error(), "Token expired") {
		t.Errorf("error should contain message: %v", err)
	}
	if !strings.Contains(err.Error(), "barndoor-login") {
		t.Errorf("error should contain default help text: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewTokenExpiredError
// ---------------------------------------------------------------------------

func TestNewTokenExpiredError(t *testing.T) {
	err := NewTokenExpiredError("session expired")
	if !strings.Contains(err.Error(), "session expired") {
		t.Errorf("error should contain message: %v", err)
	}
	// Should be a TokenExpiredError
	var tokenExpired *TokenExpiredError
	if !errors.As(err, &tokenExpired) {
		t.Error("expected TokenExpiredError type")
	}
}

// ---------------------------------------------------------------------------
// NewOAuthError
// ---------------------------------------------------------------------------

func TestNewOAuthError(t *testing.T) {
	err := NewOAuthError("OAuth failed")
	if err.Error() != "OAuth failed" {
		t.Errorf("Error() = %q, want %q", err.Error(), "OAuth failed")
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Error("expected OAuthError type")
	}
}

// ---------------------------------------------------------------------------
// NewConnectionError
// ---------------------------------------------------------------------------

func TestNewConnectionError_Timeout(t *testing.T) {
	err := NewConnectionError("https://api.example.com", fmt.Errorf("connection timeout"))
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout message, got: %v", err)
	}
	if err.URL != "https://api.example.com" {
		t.Errorf("URL = %q, want %q", err.URL, "https://api.example.com")
	}
}

func TestNewConnectionError_ConnectionRefused(t *testing.T) {
	err := NewConnectionError("https://api.example.com", fmt.Errorf("connection refused"))
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("expected connection refused message, got: %v", err)
	}
}

func TestNewConnectionError_DNSError(t *testing.T) {
	err := NewConnectionError("https://api.example.com", fmt.Errorf("no such host"))
	if !strings.Contains(err.Error(), "resolve hostname") {
		t.Errorf("expected DNS message, got: %v", err)
	}
}

func TestNewConnectionError_LookupError(t *testing.T) {
	err := NewConnectionError("https://api.example.com", fmt.Errorf("lookup failed"))
	if !strings.Contains(err.Error(), "resolve hostname") {
		t.Errorf("expected DNS message for lookup error, got: %v", err)
	}
}

func TestNewConnectionError_Default(t *testing.T) {
	err := NewConnectionError("https://api.example.com", fmt.Errorf("some other error"))
	if !strings.Contains(err.Error(), "Failed to connect") {
		t.Errorf("expected default message, got: %v", err)
	}
}

func TestConnectionError_Unwrap(t *testing.T) {
	original := fmt.Errorf("original error")
	err := NewConnectionError("https://api.example.com", original)
	if err.Unwrap() != original {
		t.Error("Unwrap should return the original error")
	}
}

// ---------------------------------------------------------------------------
// NewHTTPError
// ---------------------------------------------------------------------------

func TestNewHTTPError_400(t *testing.T) {
	err := NewHTTPError(400, "Bad Request", `{"error":"invalid"}`)
	if !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("expected HTTP 400 in message: %v", err)
	}
	if !strings.Contains(err.Error(), "Invalid request") {
		t.Errorf("expected user-friendly message for 400: %v", err)
	}
	if err.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", err.StatusCode)
	}
	if err.ResponseBody != `{"error":"invalid"}` {
		t.Errorf("ResponseBody = %q", err.ResponseBody)
	}
}

func TestNewHTTPError_401(t *testing.T) {
	err := NewHTTPError(401, "Unauthorized", "")
	if !strings.Contains(err.Error(), "Authentication failed") {
		t.Errorf("expected auth failed message for 401: %v", err)
	}
}

func TestNewHTTPError_403(t *testing.T) {
	err := NewHTTPError(403, "Forbidden", "")
	if !strings.Contains(err.Error(), "Access denied") {
		t.Errorf("expected access denied message for 403: %v", err)
	}
}

func TestNewHTTPError_404(t *testing.T) {
	err := NewHTTPError(404, "Not Found", "")
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found message for 404: %v", err)
	}
}

func TestNewHTTPError_429(t *testing.T) {
	err := NewHTTPError(429, "Too Many Requests", "")
	if !strings.Contains(err.Error(), "Rate limit") {
		t.Errorf("expected rate limit message for 429: %v", err)
	}
}

func TestNewHTTPError_500(t *testing.T) {
	err := NewHTTPError(500, "Internal Server Error", "")
	if !strings.Contains(err.Error(), "Server error") {
		t.Errorf("expected server error message for 500: %v", err)
	}
}

func TestNewHTTPError_502(t *testing.T) {
	err := NewHTTPError(502, "Bad Gateway", "")
	if !strings.Contains(err.Error(), "Server error") {
		t.Errorf("expected server error message for 502: %v", err)
	}
}

func TestNewHTTPError_Other(t *testing.T) {
	err := NewHTTPError(418, "I'm a teapot", "")
	if !strings.Contains(err.Error(), "I'm a teapot") {
		t.Errorf("expected original message for unknown status: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewServerNotFoundError
// ---------------------------------------------------------------------------

func TestNewServerNotFoundError_NoServers(t *testing.T) {
	err := NewServerNotFoundError("github", nil)
	if !strings.Contains(err.Error(), "'github' not found") {
		t.Errorf("expected server name in message: %v", err)
	}
	if !strings.Contains(err.Error(), "ListServers()") {
		t.Errorf("expected hint to ListServers: %v", err)
	}
	if err.ServerIdentifier != "github" {
		t.Errorf("ServerIdentifier = %q, want %q", err.ServerIdentifier, "github")
	}
}

func TestNewServerNotFoundError_WithServers(t *testing.T) {
	err := NewServerNotFoundError("github", []string{"slack", "jira"})
	if !strings.Contains(err.Error(), "slack, jira") {
		t.Errorf("expected available servers in message: %v", err)
	}
	if len(err.AvailableServers) != 2 {
		t.Errorf("AvailableServers length = %d, want 2", len(err.AvailableServers))
	}
}

// ---------------------------------------------------------------------------
// NewConfigurationError
// ---------------------------------------------------------------------------

func TestNewConfigurationError(t *testing.T) {
	err := NewConfigurationError("missing field")
	if err.Error() != "missing field" {
		t.Errorf("Error() = %q, want %q", err.Error(), "missing field")
	}
	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Error("expected ConfigurationError type")
	}
}

// ---------------------------------------------------------------------------
// NewTimeoutError
// ---------------------------------------------------------------------------

func TestNewTimeoutError(t *testing.T) {
	err := NewTimeoutError("operation timed out")
	if err.Error() != "operation timed out" {
		t.Errorf("Error() = %q, want %q", err.Error(), "operation timed out")
	}
	var timeoutErr *TimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Error("expected TimeoutError type")
	}
}
