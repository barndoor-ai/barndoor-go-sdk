package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// SDKOptions configures the BarndoorSDK.
type SDKOptions struct {
	// Token is the user JWT token (optional - can be set later via Authenticate).
	Token string
	// ValidateTokenOnInit controls whether the token is validated on initialization.
	ValidateTokenOnInit bool
	// Timeout is the request timeout in seconds (default: 30).
	Timeout float64
	// MaxRetries is the maximum number of retries (default: 3).
	MaxRetries int
}

// BarndoorSDK is the main client for interacting with the Barndoor Platform API.
type BarndoorSDK struct {
	// Base is the base URL of the Barndoor API.
	Base string

	token          string
	httpClient     *httpClient
	tokenValidated bool
	closed         bool
	logger         Logger
}

// NewBarndoorSDK creates a new SDK instance.
func NewBarndoorSDK(apiBaseURL string, opts *SDKOptions) (*BarndoorSDK, error) {
	if opts == nil {
		opts = &SDKOptions{}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30.0
	}
	maxRetries := opts.MaxRetries
	if maxRetries < 0 {
		return nil, NewConfigurationError("MaxRetries must be a non-negative integer")
	}
	if maxRetries == 0 {
		maxRetries = 3
	}

	baseURL, err := validateURL(apiBaseURL, "API base URL")
	if err != nil {
		return nil, err
	}
	baseURL = strings.TrimRight(baseURL, "/")

	var token string
	if opts.Token != "" {
		token, err = validateToken(opts.Token)
		if err != nil {
			return nil, err
		}
	}

	tc := timeoutConfig{
		read:    time.Duration(timeout * float64(time.Second)),
		connect: time.Duration(timeout / 3 * float64(time.Second)),
	}

	sdk := &BarndoorSDK{
		Base:       baseURL,
		token:      token,
		httpClient: newHTTPClient(tc, maxRetries),
		logger:     createScopedLogger("client"),
	}

	sdk.logger.Info(fmt.Sprintf("Initialized BarndoorSDK for %s", sdk.Base))
	return sdk, nil
}

// Token returns the current token, or an error if none is set.
func (s *BarndoorSDK) Token() (string, error) {
	if s.token == "" {
		return "", fmt.Errorf("No token available. Call Authenticate() first or provide token in SDKOptions.")
	}
	return s.token, nil
}

// Authenticate sets the authentication token for the SDK.
func (s *BarndoorSDK) Authenticate(ctx context.Context, token string) error {
	validated, err := validateToken(token)
	if err != nil {
		return err
	}
	s.token = validated
	s.tokenValidated = false

	if err := s.EnsureValidToken(ctx); err != nil {
		return err
	}

	s.logger.Info("Authentication successful")
	return nil
}

// EnsureValidToken ensures the token is valid, validating if necessary.
func (s *BarndoorSDK) EnsureValidToken(ctx context.Context) error {
	if s.token == "" {
		return fmt.Errorf("No token available. Call Authenticate() first or provide token in SDKOptions.")
	}

	if s.tokenValidated {
		return nil
	}

	// Skip validation in test/CI environments
	env := getEnvVar("BARNDOOR_ENV", "")
	lower := strings.ToLower(env)
	if lower == "test" || lower == "ci" {
		s.tokenValidated = true
		return nil
	}

	valid, err := s.ValidateCachedToken(ctx)
	if err != nil {
		return err
	}
	if !valid {
		return NewTokenError("Token validation failed. Please re-authenticate.", "")
	}

	s.tokenValidated = true
	return nil
}

// ValidateCachedToken validates the cached token by making a test API call.
func (s *BarndoorSDK) ValidateCachedToken(ctx context.Context) (bool, error) {
	if s.token == "" {
		return false, nil
	}

	config := GetStaticConfig()
	oidcConfig, err := GetOidcConfig(ctx, config.AuthIssuer)
	if err != nil {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcConfig.UserinfoEndpoint, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from OIDC discovery userinfo_endpoint
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	isValid := resp.StatusCode == http.StatusOK
	if isValid {
		s.tokenValidated = true
	}
	return isValid, nil
}

// req makes an authenticated request with automatic token validation.
func (s *BarndoorSDK) req(ctx context.Context, method, path string, opts *httpRequestOptions) (json.RawMessage, error) {
	if s.closed {
		return nil, fmt.Errorf("SDK has been closed. Create a new instance.")
	}

	if err := s.EnsureValidToken(ctx); err != nil {
		return nil, err
	}

	token, err := s.Token()
	if err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &httpRequestOptions{}
	}
	if opts.Headers == nil {
		opts.Headers = make(map[string]string)
	}
	opts.Headers["Authorization"] = "Bearer " + token

	url := s.Base + path
	return s.httpClient.request(ctx, method, url, opts)
}

// ListServers lists all MCP servers available to the caller's organization.
// It automatically fetches all pages if results are paginated.
func (s *BarndoorSDK) ListServers(ctx context.Context) ([]ServerSummary, error) {
	s.logger.Debug("Fetching server list")

	var allServers []ServerSummary
	nextPage := 1

	for {
		path := "/api/servers"
		var opts *httpRequestOptions
		if nextPage > 1 {
			opts = &httpRequestOptions{
				Params: map[string]string{"page": fmt.Sprintf("%d", nextPage)},
			}
		}

		respData, err := s.req(ctx, "GET", path, opts)
		if err != nil {
			s.logger.Error(fmt.Sprintf("Failed to list servers: %v", err))
			return nil, err
		}

		var page paginatedResponse
		if err := json.Unmarshal(respData, &page); err != nil {
			return nil, fmt.Errorf("failed to parse server list response: %w", err)
		}

		allServers = append(allServers, page.Data...)

		if page.Pagination.NextPage == nil {
			break
		}
		nextPage = *page.Pagination.NextPage
	}

	s.logger.Info(fmt.Sprintf("Retrieved %d servers total", len(allServers)))
	return allServers, nil
}

// GetServer gets detailed information about a specific server.
func (s *BarndoorSDK) GetServer(ctx context.Context, serverID string) (*ServerDetail, error) {
	validatedID, err := validateServerID(serverID)
	if err != nil {
		return nil, err
	}

	s.logger.Info(fmt.Sprintf("Fetching server details for %s", validatedID))

	var endpoint string
	if isUUID(validatedID) {
		endpoint = fmt.Sprintf("/api/servers/%s", validatedID)
	} else {
		endpoint = fmt.Sprintf("/api/servers/by-slug/%s", validatedID)
	}

	respData, err := s.req(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var server ServerDetail
	if err := json.Unmarshal(respData, &server); err != nil {
		return nil, fmt.Errorf("failed to parse server detail response: %w", err)
	}

	return &server, nil
}

// InitiateConnection initiates an OAuth connection flow for a server.
// It returns the auth URL to open in a browser, or an empty string if none was provided.
func (s *BarndoorSDK) InitiateConnection(ctx context.Context, serverID string, returnURL string) (string, error) {
	validatedID, err := validateServerID(serverID)
	if err != nil {
		return "", err
	}

	if returnURL != "" {
		if _, err := validateURL(returnURL, "Return URL"); err != nil {
			return "", err
		}
	}

	s.logger.Info(fmt.Sprintf("Initiating connection for server %s", validatedID))

	var endpoint string
	if isUUID(validatedID) {
		endpoint = fmt.Sprintf("/api/servers/%s/connect", validatedID)
	} else {
		endpoint = fmt.Sprintf("/api/servers/by-slug/%s/connect", validatedID)
	}

	opts := &httpRequestOptions{
		JSON: map[string]any{},
	}
	if returnURL != "" {
		opts.Params = map[string]string{"return_url": returnURL}
	}

	respData, err := s.req(ctx, "POST", endpoint, opts)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			if httpErr.StatusCode == 500 && strings.Contains(httpErr.ResponseBody, "OAuth server configuration not found") {
				return "", fmt.Errorf("Server is missing OAuth configuration. Ask an admin to configure credentials before initiating a connection.")
			}
		}
		return "", err
	}

	var resp connectionInitiationResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse connection initiation response: %w", err)
	}

	return resp.AuthURL, nil
}

// GetConnectionStatus gets the user's connection status for a specific server.
func (s *BarndoorSDK) GetConnectionStatus(ctx context.Context, serverID string) (string, error) {
	validatedID, err := validateServerID(serverID)
	if err != nil {
		return "", err
	}

	s.logger.Info(fmt.Sprintf("Checking connection status for server %s", validatedID))

	var endpoint string
	if isUUID(validatedID) {
		endpoint = fmt.Sprintf("/api/servers/%s/connection", validatedID)
	} else {
		endpoint = fmt.Sprintf("/api/servers/by-slug/%s/connection", validatedID)
	}

	respData, err := s.req(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}

	var resp connectionStatusResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", fmt.Errorf("failed to parse connection status response: %w", err)
	}

	return resp.Status, nil
}

// DisconnectServer disconnects from a specific MCP server.
func (s *BarndoorSDK) DisconnectServer(ctx context.Context, serverID string) error {
	validatedID, err := validateServerID(serverID)
	if err != nil {
		return err
	}

	s.logger.Info(fmt.Sprintf("Disconnecting from server %s", validatedID))

	var endpoint string
	if isUUID(validatedID) {
		endpoint = fmt.Sprintf("/api/servers/%s/connection", validatedID)
	} else {
		endpoint = fmt.Sprintf("/api/servers/by-slug/%s/connection", validatedID)
	}

	_, err = s.req(ctx, "DELETE", endpoint, nil)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok && httpErr.StatusCode == 404 {
			return fmt.Errorf("Connection not found for server %s. Server may not be connected.", validatedID)
		}
		return err
	}

	s.logger.Info(fmt.Sprintf("Successfully disconnected from server %s", validatedID))
	return nil
}

// EnsureServerConnected ensures a server is connected, initiating OAuth if needed.
func (s *BarndoorSDK) EnsureServerConnected(ctx context.Context, serverIdentifier string, pollSeconds int) error {
	if pollSeconds <= 0 {
		pollSeconds = 60
	}

	// 1. Locate server
	target, err := s.GetServer(ctx, serverIdentifier)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok && httpErr.StatusCode == 404 {
			return NewServerNotFoundError(serverIdentifier, nil)
		}
		return err
	}

	if target.ConnectionStatus == ConnectionStatusConnected {
		return nil // Already connected
	}

	// 2. Start OAuth flow
	connectionIdentifier := target.Slug
	if connectionIdentifier == "" {
		connectionIdentifier = serverIdentifier
	}

	authURL, err := s.InitiateConnection(ctx, connectionIdentifier, "")
	if err != nil {
		return err
	}

	if authURL == "" {
		return fmt.Errorf("Registry did not return auth_url")
	}

	// 3. Open browser
	if err := openBrowser(authURL); err != nil {
		s.logger.Warn(fmt.Sprintf("Failed to open browser: %v", err))
	}

	// 4. Poll until connected or timeout
	for i := 0; i < pollSeconds; i++ {
		status, err := s.GetConnectionStatus(ctx, connectionIdentifier)
		if err != nil {
			return err
		}
		if status == string(ConnectionStatusConnected) {
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("OAuth connection was not completed in time")
}

// Close closes the SDK and releases resources.
func (s *BarndoorSDK) Close() {
	if !s.closed {
		s.httpClient.close()
		s.closed = true
	}
}

// openBrowser opens a URL in the user's default browser.
// Only http and https URLs are allowed to prevent command injection.
func openBrowser(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("refusing to open non-HTTP URL scheme %q", parsed.Scheme)
	}
	sanitized := parsed.String()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", sanitized) // #nosec G204 -- URL scheme validated above
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "Start-Process", sanitized) // #nosec G204 -- URL scheme validated above
	default:
		cmd = exec.Command("xdg-open", sanitized) // #nosec G204 -- URL scheme validated above
	}
	return cmd.Start()
}
