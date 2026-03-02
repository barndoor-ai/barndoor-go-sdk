package barndoor

import (
	"fmt"
	"strings"
)

// BarndoorError is the base error type for all Barndoor SDK errors.
type BarndoorError struct {
	Message string
}

func (e *BarndoorError) Error() string {
	return e.Message
}

// AuthenticationError is returned when authentication fails.
type AuthenticationError struct {
	BarndoorError
	ErrorCode string
}

// TokenError is returned when token operations fail.
type TokenError struct {
	AuthenticationError
	HelpText string
}

func NewTokenError(message string, helpText string) *TokenError {
	full := message
	if helpText != "" {
		full += " " + helpText
	} else {
		full += " Run 'barndoor-login' to authenticate."
	}
	return &TokenError{
		AuthenticationError: AuthenticationError{
			BarndoorError: BarndoorError{Message: full},
		},
		HelpText: helpText,
	}
}

// TokenExpiredError is returned when a token has expired.
type TokenExpiredError struct {
	TokenError
}

func NewTokenExpiredError(message string) *TokenExpiredError {
	return &TokenExpiredError{
		TokenError: *NewTokenError(message, ""),
	}
}

// TokenValidationError is returned when token validation fails.
type TokenValidationError struct {
	TokenError
}

// OAuthError is returned when OAuth authentication fails.
type OAuthError struct {
	AuthenticationError
}

func NewOAuthError(message string) *OAuthError {
	return &OAuthError{
		AuthenticationError: AuthenticationError{
			BarndoorError: BarndoorError{Message: message},
		},
	}
}

// ConnectionError is returned when unable to connect to the Barndoor API.
type ConnectionError struct {
	BarndoorError
	URL           string
	OriginalError error
}

func NewConnectionError(url string, originalError error) *ConnectionError {
	var userMessage string
	errStr := strings.ToLower(originalError.Error())

	switch {
	case strings.Contains(errStr, "timeout"):
		userMessage = fmt.Sprintf("Connection to %s timed out. Please check your internet connection and try again.", url)
	case strings.Contains(errStr, "connection refused"):
		userMessage = fmt.Sprintf("Could not connect to %s. The service may be unavailable.", url)
	case strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup"):
		userMessage = fmt.Sprintf("Could not resolve hostname for %s. Please check the URL and your DNS settings.", url)
	default:
		userMessage = fmt.Sprintf("Failed to connect to %s. Please check your internet connection.", url)
	}

	return &ConnectionError{
		BarndoorError: BarndoorError{Message: userMessage},
		URL:           url,
		OriginalError: originalError,
	}
}

func (e *ConnectionError) Unwrap() error {
	return e.OriginalError
}

// HTTPError is returned for HTTP error responses.
type HTTPError struct {
	BarndoorError
	StatusCode   int
	ResponseBody string
}

func NewHTTPError(statusCode int, message string, responseBody string) *HTTPError {
	userMessage := createUserFriendlyMessage(statusCode, message)
	return &HTTPError{
		BarndoorError: BarndoorError{Message: userMessage},
		StatusCode:    statusCode,
		ResponseBody:  responseBody,
	}
}

func createUserFriendlyMessage(statusCode int, message string) string {
	base := fmt.Sprintf("Request failed (HTTP %d)", statusCode)

	switch {
	case statusCode == 400:
		return base + ": Invalid request. Please check your input parameters."
	case statusCode == 401:
		return base + ": Authentication failed. Please check your token or re-authenticate."
	case statusCode == 403:
		return base + ": Access denied. You don't have permission for this operation."
	case statusCode == 404:
		return base + ": Resource not found. Please check the server ID or URL."
	case statusCode == 429:
		return base + ": Rate limit exceeded. Please wait before making more requests."
	case statusCode >= 500 && statusCode < 600:
		return base + ": Server error. Please try again later or contact support."
	default:
		return base + ": " + message
	}
}

// ServerNotFoundError is returned when a requested server is not found.
type ServerNotFoundError struct {
	BarndoorError
	ServerIdentifier string
	AvailableServers []string
}

func NewServerNotFoundError(serverIdentifier string, availableServers []string) *ServerNotFoundError {
	message := fmt.Sprintf("Server '%s' not found", serverIdentifier)
	if len(availableServers) > 0 {
		message += fmt.Sprintf(". Available servers: %s", strings.Join(availableServers, ", "))
	} else {
		message += ". Use ListServers() to see available servers."
	}

	return &ServerNotFoundError{
		BarndoorError:    BarndoorError{Message: message},
		ServerIdentifier: serverIdentifier,
		AvailableServers: availableServers,
	}
}

// ConfigurationError is returned when there's an issue with SDK configuration.
type ConfigurationError struct {
	BarndoorError
}

func NewConfigurationError(message string) *ConfigurationError {
	return &ConfigurationError{
		BarndoorError: BarndoorError{Message: message},
	}
}

// TimeoutError is returned when an operation times out.
type TimeoutError struct {
	BarndoorError
}

func NewTimeoutError(message string) *TimeoutError {
	return &TimeoutError{
		BarndoorError: BarndoorError{Message: message},
	}
}
