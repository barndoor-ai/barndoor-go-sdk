package barndoor

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	slugRegex = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// validateURL checks that the given string is a valid URL.
func validateURL(rawURL, name string) (string, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", NewConfigurationError(fmt.Sprintf("%s must be a non-empty string", name))
	}
	_, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", NewConfigurationError(fmt.Sprintf("%s must be a valid URL", name))
	}
	return rawURL, nil
}

// validateToken checks that the token is a valid JWT format.
func validateToken(token string) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", NewTokenError("Token must be a non-empty string", "")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", NewTokenError("Token must be a valid JWT", "")
	}
	return token, nil
}

// validateServerID checks that the server ID is a valid UUID or slug.
func validateServerID(serverID string) (string, error) {
	if strings.TrimSpace(serverID) == "" {
		return "", fmt.Errorf("Server ID must be a non-empty string")
	}

	lowerID := strings.ToLower(serverID)
	if !uuidRegex.MatchString(lowerID) && !slugRegex.MatchString(lowerID) {
		return "", fmt.Errorf("Server ID must be a valid UUID or slug (lowercase letters, numbers, and hyphens only)")
	}

	return serverID, nil
}

// isUUID checks if a string is a UUID.
func isUUID(s string) bool {
	return uuidRegex.MatchString(strings.ToLower(s))
}
