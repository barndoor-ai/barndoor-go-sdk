package barndoor

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LoginInteractiveOptions configures the interactive login flow.
type LoginInteractiveOptions struct {
	// AuthIssuer is the OIDC issuer URL.
	AuthIssuer string
	// AuthDomain is deprecated; use AuthIssuer.
	AuthDomain string
	// ClientID is the OAuth client ID.
	ClientID string
	// ClientSecret is the OAuth client secret.
	ClientSecret string // #nosec G117 -- OAuth client secret config field
	// Audience is the API audience identifier.
	Audience string
	// BaseURL is the base URL of the Barndoor API.
	BaseURL string
	// Port is the local port for OAuth callback (default: 52765).
	Port int
}

// LoginInteractive performs an interactive OAuth login and returns an initialized SDK.
//
// It opens the system browser for OAuth authentication, waits for the user to
// complete login, exchanges the authorization code for a JWT, and returns a
// configured BarndoorSDK instance.
//
// Auth configuration is baked in per environment (set via BARNDOOR_ENV).
// You typically only need to set AGENT_CLIENT_ID and AGENT_CLIENT_SECRET.
func LoginInteractive(ctx context.Context, opts *LoginInteractiveOptions) (*BarndoorSDK, error) {
	if opts == nil {
		opts = &LoginInteractiveOptions{}
	}

	logger := createScopedLogger("quickstart")
	logger.Info("Starting interactive login flow")

	config := GetStaticConfig()

	// Determine auth issuer
	var authIssuer string
	switch {
	case opts.AuthIssuer != "":
		authIssuer = opts.AuthIssuer
	case opts.AuthDomain != "":
		if strings.HasPrefix(opts.AuthDomain, "http") {
			authIssuer = opts.AuthDomain
		} else {
			authIssuer = "https://" + opts.AuthDomain
		}
	default:
		authIssuer = config.AuthIssuer
	}

	clientID := opts.ClientID
	if clientID == "" {
		clientID = config.ClientID
	}
	clientSecret := opts.ClientSecret
	if clientSecret == "" {
		clientSecret = config.ClientSecret
	}
	audience := opts.Audience
	if audience == "" {
		audience = config.APIAudience
	}
	port := opts.Port
	if port == 0 {
		port = 52765
	}

	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("AGENT_CLIENT_ID / AGENT_CLIENT_SECRET not set – create a .env file or export in the shell")
	}

	// 1. Try cached token first
	cachedToken, _ := LoadUserToken()
	if cachedToken != "" {
		var baseURL string
		if HasOrganizationInfo(cachedToken) {
			dynConfig, err := GetDynamicConfig(cachedToken, true, "")
			if err == nil {
				baseURL = dynConfig.BaseURL
			}
		}
		if baseURL == "" {
			baseURL = config.BaseURL
		}

		sdk, err := NewBarndoorSDK(baseURL, &SDKOptions{Token: cachedToken})
		if err == nil {
			valid, _ := sdk.ValidateCachedToken(ctx)
			if valid {
				logger.Info("Using cached valid token")
				return sdk, nil
			}
		}
		logger.Info("Cached token invalid, starting OAuth flow")
	} else {
		logger.Info("No cached token, starting OAuth flow")
	}

	// 2. Start interactive PKCE flow
	manual := getEnvVar("BARNDOOR_MANUAL_CODE", "") == "1" || getEnvVar("BARNDOOR_MANUAL_CODE", "") == "true"

	var redirectURI string
	var resultCh <-chan callbackResult

	if manual {
		host := getEnvVar("BARNDOOR_REDIRECT_HOST", "127.0.0.1")
		if strings.HasPrefix(host, "http") {
			redirectURI = fmt.Sprintf("%s:%d/cb", host, port)
		} else {
			redirectURI = fmt.Sprintf("http://%s:%d/cb", host, port)
		}
	} else {
		var err error
		redirectURI, resultCh, err = StartLocalCallbackServer(port)
		if err != nil {
			return nil, err
		}
	}

	pkceManager := NewPKCEManager()
	authURL, err := pkceManager.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Audience:    audience,
		Issuer:      authIssuer,
	})
	if err != nil {
		return nil, err
	}

	logger.Info(fmt.Sprintf("Auth URL: %s", authURL))

	// Open browser
	if err := openBrowserFunc(authURL); err != nil {
		logger.Warn(fmt.Sprintf("Failed to open browser automatically. Please visit: %s", authURL))
	} else {
		logger.Info("Please complete login in your browser...")
	}

	// Obtain authorization code
	var code string
	if manual {
		fmt.Print("Paste the full redirected URL (or just the code= value): ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			input := strings.TrimSpace(scanner.Text())
			// Try to parse as URL
			if parsed, err := url.Parse(input); err == nil && parsed.Query().Get("code") != "" {
				code = parsed.Query().Get("code")
			} else {
				code = input
			}
		}
	} else {
		// Wait for callback with timeout
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()

		select {
		case result := <-resultCh:
			if result.err != nil {
				return nil, result.err
			}
			code = result.code
		case <-timer.C:
			return nil, fmt.Errorf(
				"OAuth callback timeout after 2 minutes. "+
					"This usually means the callback URL is not registered. "+
					"Please add \"%s\" to Allowed Callback URLs in your application settings.", redirectURI)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Exchange code for token
	tokenData, err := pkceManager.ExchangeCodeForToken(ctx, TokenExchangeParams{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
		Issuer:       authIssuer,
	})
	if err != nil {
		return nil, err
	}

	// Extract access token
	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("no access_token in token response")
	}

	// Save token data
	td := &TokenData{AccessToken: accessToken}
	if rt, ok := tokenData["refresh_token"].(string); ok {
		td.RefreshToken = rt
	}
	if tt, ok := tokenData["token_type"].(string); ok {
		td.TokenType = tt
	}
	if err := SaveUserTokenData(td); err != nil {
		logger.Warn(fmt.Sprintf("Failed to save token: %v", err))
	}

	// Determine base URL
	var finalBaseURL string
	if opts.BaseURL != "" {
		finalBaseURL = opts.BaseURL
	} else if HasOrganizationInfo(accessToken) {
		dynConfig, err := GetDynamicConfig(accessToken, true, "")
		if err == nil {
			finalBaseURL = dynConfig.BaseURL
		}
	}
	if finalBaseURL == "" {
		logger.Warn("Token has no organization information, using static config")
		finalBaseURL = GetStaticConfig().BaseURL
	}

	return NewBarndoorSDK(finalBaseURL, &SDKOptions{Token: accessToken})
}

// EnsureServerConnectedQuickstart is a convenience wrapper around EnsureServerConnected
// that adds helpful logging for interactive use.
func EnsureServerConnectedQuickstart(ctx context.Context, sdk *BarndoorSDK, serverIdentifier string, timeout int) error {
	if timeout <= 0 {
		timeout = 90
	}

	logger := createScopedLogger("quickstart")
	logger.Info(fmt.Sprintf("Ensuring %s server is connected", serverIdentifier))

	if err := sdk.EnsureServerConnected(ctx, serverIdentifier, timeout); err != nil {
		if _, ok := err.(*ServerNotFoundError); ok {
			logger.Error(fmt.Sprintf("Server '%s' not found", serverIdentifier))
		} else {
			logger.Error(fmt.Sprintf("Failed to connect to %s: %v", serverIdentifier, err))
		}
		return err
	}

	logger.Info(fmt.Sprintf("Server %s connected successfully", serverIdentifier))
	return nil
}

// MCPConnectionParams holds parameters for connecting to an MCP server.
type MCPConnectionParams struct {
	URL       string            `json:"url"`
	Transport string            `json:"transport"`
	Headers   map[string]string `json:"headers"`
}

// MakeMCPConnectionParams creates MCP connection parameters for a server.
//
// Returns connection parameters that can be used with any MCP client framework.
func MakeMCPConnectionParams(ctx context.Context, sdk *BarndoorSDK, serverSlugOrID string) (*MCPConnectionParams, string, error) {
	// Fetch server to validate it exists and get slug
	server, err := sdk.GetServer(ctx, serverSlugOrID)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok && httpErr.StatusCode == 404 {
			return nil, "", NewServerNotFoundError(serverSlugOrID, nil)
		}
		return nil, "", err
	}

	// MCP endpoint expects slugs, not UUIDs
	mcpIdentifier := server.Slug
	if mcpIdentifier == "" {
		mcpIdentifier = serverSlugOrID
	}

	token, err := sdk.Token()
	if err != nil {
		return nil, "", err
	}

	// Build MCP URL
	var mcpURL string
	if HasOrganizationInfo(token) {
		dynConfig, err := GetDynamicConfig(token, true, "")
		if err == nil {
			mcpURL = dynConfig.BaseURL + "/mcp/" + mcpIdentifier
		}
	}
	if mcpURL == "" {
		staticConfig := GetStaticConfig()
		mcpURL = staticConfig.BaseURL + "/mcp/" + mcpIdentifier
	}

	params := &MCPConnectionParams{
		URL:       mcpURL,
		Transport: "streamable-http",
		Headers: map[string]string{
			"Accept":                   "application/json, text/event-stream",
			"Authorization":            "Bearer " + token,
			"x-barndoor-session-id":    uuid.New().String(),
		},
	}

	return params, mcpURL, nil
}
