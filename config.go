package barndoor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// AuthEnvironmentConfig holds baked-in auth configuration for an environment.
type AuthEnvironmentConfig struct {
	Issuer   string
	Audience string
	BaseURL  string
}

// AuthConfig holds all pre-configured environment settings.
var AuthConfig = map[string]AuthEnvironmentConfig{
	// Trial environments (Keycloak) - DEFAULT
	"production": {
		Issuer:   "https://auth.trial.barndoor.ai/realms/barndoor",
		Audience: "https://barndoor.ai/",
		BaseURL:  "https://{org_slug}.platform.barndoor.ai",
	},
	"uat": {
		Issuer:   "https://auth.barndooruat.com/realms/barndoor",
		Audience: "https://barndoor.ai/",
		BaseURL:  "https://{org_slug}.trial.barndooruat.com",
	},
	"dev": {
		Issuer:   "https://auth.barndoordev.com/realms/barndoor",
		Audience: "https://barndoor.ai/",
		BaseURL:  "https://{org_slug}.platform.barndoordev.com",
	},
	// Enterprise environments (Auth0)
	"enterprise-production": {
		Issuer:   "https://auth.barndoor.ai",
		Audience: "https://barndoor.ai/",
		BaseURL:  "https://{org_slug}.mcp.barndoor.ai",
	},
	"enterprise-uat": {
		Issuer:   "https://auth.barndooruat.com",
		Audience: "https://barndoor.ai/",
		BaseURL:  "https://{org_slug}.mcp.barndooruat.com",
	},
	"enterprise-dev": {
		Issuer:   "https://auth.barndoordev.com",
		Audience: "https://barndoor.ai/",
		BaseURL:  "https://{org_slug}.mcp.barndoordev.com",
	},
	// Local development (Keycloak)
	"localdev": {
		Issuer:   "http://localhost:8080/realms/barndoor",
		Audience: "https://barndoor.ai/",
		BaseURL:  "http://localhost:8000",
	},
}

// BarndoorConfig holds unified configuration for the SDK.
type BarndoorConfig struct {
	AuthIssuer     string
	ClientID       string
	ClientSecret   string // #nosec G117 -- OAuth client secret config field
	APIAudience    string
	BaseURL        string
	Environment    string
	PromptForLogin bool
	SkipLoginLocal bool
}

// BarndoorConfigOptions are options for creating a BarndoorConfig.
type BarndoorConfigOptions struct {
	AuthIssuer     string
	AuthDomain     string // deprecated: use AuthIssuer
	ClientID       string
	ClientSecret   string // #nosec G117 -- OAuth client secret config field
	APIAudience    string
	BaseURL        string
	Environment    string
	PromptForLogin bool
	SkipLoginLocal bool
}

// normalizeEnvironmentMode converts various environment mode strings to canonical form.
func normalizeEnvironmentMode(env string) string {
	envModeMap := map[string]string{
		"production":              "production",
		"prod":                    "production",
		"uat":                     "uat",
		"dev":                     "dev",
		"development":             "dev",
		"enterprise-production":   "enterprise-production",
		"enterprise-prod":         "enterprise-production",
		"enterprise-uat":          "enterprise-uat",
		"enterprise-dev":          "enterprise-dev",
		"enterprise":              "enterprise-production",
		"localdev":                "localdev",
		"local":                   "localdev",
	}
	if mapped, ok := envModeMap[strings.ToLower(env)]; ok {
		return mapped
	}
	return "production"
}

// getEnvVar returns an environment variable value or a default.
func getEnvVar(name, defaultValue string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return defaultValue
}

// NewBarndoorConfig creates a new configuration from options.
func NewBarndoorConfig(opts *BarndoorConfigOptions) *BarndoorConfig {
	if opts == nil {
		opts = &BarndoorConfigOptions{}
	}

	// Determine environment
	rawEnv := opts.Environment
	if rawEnv == "" {
		rawEnv = getEnvVar("MODE", "")
		if rawEnv == "" {
			rawEnv = getEnvVar("BARNDOOR_ENV", "production")
		}
	}
	environment := normalizeEnvironmentMode(rawEnv)

	// Get baked-in config for this environment
	authCfg, ok := AuthConfig[environment]
	if !ok {
		authCfg = AuthConfig["production"]
	}

	// Determine auth issuer
	var authIssuer string
	switch {
	case opts.AuthIssuer != "":
		authIssuer = opts.AuthIssuer
	case getEnvVar("AUTH_URL", "") != "":
		authIssuer = getEnvVar("AUTH_URL", "")
	case opts.AuthDomain != "":
		if strings.HasPrefix(opts.AuthDomain, "http") {
			authIssuer = opts.AuthDomain
		} else {
			authIssuer = "https://" + opts.AuthDomain
		}
	case getEnvVar("AUTH_DOMAIN", "") != "":
		domain := getEnvVar("AUTH_DOMAIN", "")
		if strings.HasPrefix(domain, "http") {
			authIssuer = domain
		} else {
			authIssuer = "https://" + domain
		}
	default:
		authIssuer = authCfg.Issuer
	}

	// Client ID
	clientID := opts.ClientID
	if clientID == "" {
		clientID = getEnvVar("AGENT_CLIENT_ID", "")
		if clientID == "" {
			clientID = getEnvVar("AUTH_CLIENT_ID", "")
		}
	}

	// Client secret
	clientSecret := opts.ClientSecret
	if clientSecret == "" {
		clientSecret = getEnvVar("AGENT_CLIENT_SECRET", "")
		if clientSecret == "" {
			clientSecret = getEnvVar("AUTH_CLIENT_SECRET", "")
		}
	}

	// API audience
	apiAudience := opts.APIAudience
	if apiAudience == "" {
		apiAudience = getEnvVar("API_AUDIENCE", authCfg.Audience)
	}

	// Base URL
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = getEnvVar("BARNDOOR_API", "")
		if baseURL == "" {
			baseURL = getEnvVar("BARNDOOR_URL", authCfg.BaseURL)
		}
	}

	return &BarndoorConfig{
		AuthIssuer:     authIssuer,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		APIAudience:    apiAudience,
		BaseURL:        baseURL,
		Environment:    environment,
		PromptForLogin: opts.PromptForLogin,
		SkipLoginLocal: opts.SkipLoginLocal,
	}
}

// GetStaticConfig returns a static configuration without organization substitution.
func GetStaticConfig() *BarndoorConfig {
	return NewBarndoorConfig(nil)
}

// GetDynamicConfig returns a configuration with org slug substituted from JWT claims.
func GetDynamicConfig(jwtToken string, requireOrganization bool, fallbackOrgID string) (*BarndoorConfig, error) {
	config := NewBarndoorConfig(nil)

	orgResult := extractOrganizationIDSafe(jwtToken)

	if orgResult.HasOrganization {
		raw := strings.TrimSpace(strings.ToLower(orgResult.OrganizationID))
		// Validate subdomain format
		matched, _ := regexp.MatchString(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, raw)
		if !matched {
			return nil, NewConfigurationError("Invalid organization subdomain format from token")
		}
		config.BaseURL = strings.ReplaceAll(config.BaseURL, "{org_slug}", raw)
		return config, nil
	}

	if fallbackOrgID != "" {
		config.BaseURL = strings.ReplaceAll(config.BaseURL, "{org_slug}", fallbackOrgID)
		return config, nil
	}

	if requireOrganization {
		errMsg := orgResult.Error
		if errMsg == "" {
			errMsg = "No organization information found in token"
		}
		return nil, NewConfigurationError(
			fmt.Sprintf("Failed to extract organization ID from token: %s. "+
				"This token may be for a personal account or may be missing organization claims. "+
				"Consider using GetStaticConfig() for organization-independent operations or "+
				"provide a fallbackOrganizationId.", errMsg),
		)
	}

	return config, nil
}

// Validate checks the configuration for required fields.
func (c *BarndoorConfig) Validate() error {
	if strings.TrimSpace(c.AuthIssuer) == "" {
		return NewConfigurationError("AuthIssuer is required")
	}
	if strings.TrimSpace(c.APIAudience) == "" {
		return NewConfigurationError("APIAudience is required")
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return NewConfigurationError("BaseURL is required")
	}
	return nil
}

// OrganizationExtractionResult holds the result of extracting org info from JWT.
type OrganizationExtractionResult struct {
	OrganizationID  string
	HasOrganization bool
	Error           string
}

// extractOrganizationIDSafe extracts organization ID from JWT token with graceful fallback.
func extractOrganizationIDSafe(jwtToken string) OrganizationExtractionResult {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return OrganizationExtractionResult{
			HasOrganization: false,
			Error:           "Invalid JWT format - expected 3 parts separated by dots",
		}
	}

	// Base64url decode the payload
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return OrganizationExtractionResult{
			HasOrganization: false,
			Error:           "Failed to parse JWT payload - token may be corrupted",
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return OrganizationExtractionResult{
			HasOrganization: false,
			Error:           "Failed to parse JWT payload - token may be corrupted",
		}
	}

	// Try multiple possible locations for organization information
	var orgSlug string

	// Check user object first
	if user, ok := claims["user"].(map[string]any); ok {
		if v, ok := user["organization_name"].(string); ok && v != "" {
			orgSlug = v
		} else if v, ok := user["organization_slug"].(string); ok && v != "" {
			orgSlug = v
		}
	}

	// Check custom claims and standard locations
	if orgSlug == "" {
		candidates := []string{
			"organization_name",
			"https://barndoor.ai/organization_slug",
			"organization_slug",
			"org_slug",
		}
		for _, key := range candidates {
			if v, ok := claims[key].(string); ok && v != "" {
				orgSlug = v
				break
			}
		}
	}

	if strings.TrimSpace(orgSlug) == "" {
		return OrganizationExtractionResult{
			HasOrganization: false,
			Error:           "No organization information found in token. This token may be for a personal account or may be missing organization claims.",
		}
	}

	return OrganizationExtractionResult{
		OrganizationID:  strings.TrimSpace(orgSlug),
		HasOrganization: true,
	}
}

// CheckTokenOrganization checks if a JWT token contains organization information.
func CheckTokenOrganization(jwtToken string) OrganizationExtractionResult {
	return extractOrganizationIDSafe(jwtToken)
}

// HasOrganizationInfo checks if a JWT token has organization information.
func HasOrganizationInfo(jwtToken string) bool {
	return extractOrganizationIDSafe(jwtToken).HasOrganization
}

// base64URLDecode decodes a base64url-encoded string.
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
