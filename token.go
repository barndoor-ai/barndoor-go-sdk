package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TokenStorage provides an interface for persisting token data.
type TokenStorage interface {
	LoadToken() (*TokenData, error)
	SaveToken(tokenData *TokenData) error
	ClearToken() error
}

// FileTokenStorage stores tokens in the filesystem.
type FileTokenStorage struct {
	tokenFile string
	mu        sync.Mutex
}

// NewFileTokenStorage creates a new file-based token storage.
func NewFileTokenStorage() *FileTokenStorage {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = os.TempDir()
	}
	return &FileTokenStorage{
		tokenFile: filepath.Join(homeDir, ".barndoor", "token.json"),
	}
}

// LoadToken loads token data from the file.
func (s *FileTokenStorage) LoadToken() (*TokenData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to load token: %w", err)
	}

	var tokenData TokenData
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse token data: %w", err)
	}

	return &tokenData, nil
}

// SaveToken saves token data to the file.
func (s *FileTokenStorage) SaveToken(tokenData *TokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(s.tokenFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return NewTokenError(fmt.Sprintf("Failed to save token: %v", err), "")
	}

	data, err := json.MarshalIndent(tokenData, "", "  ") // #nosec G117 -- intentionally persisting OAuth tokens to local file (0600 perms)
	if err != nil {
		return NewTokenError(fmt.Sprintf("Failed to save token: %v", err), "")
	}

	// Write with restrictive permissions
	if err := os.WriteFile(s.tokenFile, data, 0600); err != nil {
		return NewTokenError(fmt.Sprintf("Failed to save token: %v", err), "")
	}

	return nil
}

// ClearToken removes the token file.
func (s *FileTokenStorage) ClearToken() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.tokenFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear token: %w", err)
	}
	return nil
}

// GetTokenStorage returns the default token storage.
func GetTokenStorage() TokenStorage {
	return NewFileTokenStorage()
}

// TokenManager handles token validation, refresh, and storage.
type TokenManager struct {
	storage TokenStorage
	mu      sync.Mutex
	logger  Logger
}

// NewTokenManager creates a new token manager.
func NewTokenManager() *TokenManager {
	return &TokenManager{
		storage: GetTokenStorage(),
		logger:  createScopedLogger("token"),
	}
}

// GetValidToken returns a valid access token, refreshing if necessary.
func (m *TokenManager) GetValidToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tokenData, err := m.storage.LoadToken()
	if err != nil {
		return "", err
	}
	if tokenData == nil {
		return "", NewTokenError("No token found. Please authenticate.", "")
	}

	// Check if we should proactively refresh
	if m.shouldRefreshToken(tokenData) && tokenData.RefreshToken != "" {
		m.logger.Debug("Proactively refreshing token before expiration")
		newTokenData, err := m.refreshToken(ctx, tokenData)
		if err == nil {
			merged := mergeTokenData(tokenData, newTokenData)
			_ = m.storage.SaveToken(merged)
			return merged.AccessToken, nil
		}
		m.logger.Warn(fmt.Sprintf("Proactive refresh failed: %v", err))
	}

	// Validate or refresh
	validatedData, err := m.validateOrRefresh(ctx, tokenData)
	if err != nil {
		m.logger.Error(fmt.Sprintf("Token validation/refresh failed: %v", err))
		return "", NewTokenExpiredError("Token expired and refresh failed. Please re-authenticate.")
	}

	_ = m.storage.SaveToken(validatedData)
	return validatedData.AccessToken, nil
}

func (m *TokenManager) shouldRefreshToken(tokenData *TokenData) bool {
	claims, err := decodeJWTPayload(tokenData.AccessToken)
	if err != nil {
		return true
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return true
	}

	// Refresh if token expires within 5 minutes
	now := float64(time.Now().Unix())
	return exp-now < 300
}

func (m *TokenManager) validateOrRefresh(ctx context.Context, tokenData *TokenData) (*TokenData, error) {
	cfg := GetStaticConfig()

	// Fast path: local JWT verification
	result := VerifyJWTLocal(ctx, tokenData.AccessToken, cfg.AuthIssuer, cfg.APIAudience)

	if result == JWTValid {
		m.logger.Debug("Token validated locally")
		return tokenData, nil
	}

	if result == JWTInvalid {
		// Try remote validation
		m.logger.Debug("Local validation failed, trying remote")
		if m.isTokenValidRemote(ctx, tokenData.AccessToken) {
			m.logger.Debug("Token validated remotely")
			return tokenData, nil
		}
	}

	// Token is invalid or expired - attempt refresh
	m.logger.Info("Token invalid or expired, attempting refresh")
	if tokenData.RefreshToken != "" {
		newTokenData, err := m.refreshToken(ctx, tokenData)
		if err != nil {
			return nil, err
		}
		return mergeTokenData(tokenData, newTokenData), nil
	}

	return nil, NewTokenExpiredError("Token expired and no refresh token available")
}

func (m *TokenManager) isTokenValidRemote(ctx context.Context, token string) bool {
	cfg := GetStaticConfig()
	oidcConfig, err := GetOidcConfig(ctx, cfg.AuthIssuer)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcConfig.UserinfoEndpoint, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from OIDC discovery userinfo_endpoint
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func (m *TokenManager) refreshToken(ctx context.Context, tokenData *TokenData) (*TokenData, error) {
	if tokenData.RefreshToken == "" {
		return nil, NewTokenError("No refresh token available", "")
	}

	cfg := GetStaticConfig()

	oidcConfig, err := GetOidcConfig(ctx, cfg.AuthIssuer)
	if err != nil {
		return nil, NewTokenError(fmt.Sprintf("Failed to get OIDC config: %v", err), "")
	}

	payload := fmt.Sprintf("grant_type=refresh_token&client_id=%s&refresh_token=%s",
		cfg.ClientID, tokenData.RefreshToken)
	if cfg.ClientSecret != "" {
		payload += "&client_secret=" + cfg.ClientSecret
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcConfig.TokenEndpoint, strings.NewReader(payload))
	if err != nil {
		return nil, NewTokenError(fmt.Sprintf("Token refresh failed: %v", err), "")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from OIDC discovery token_endpoint
	if err != nil {
		return nil, NewTokenError("Network error during token refresh. Please check your connection.", "")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewTokenError(fmt.Sprintf("Token refresh failed: %v", err), "")
	}

	switch {
	case resp.StatusCode == 400:
		var errorData map[string]any
		_ = json.Unmarshal(body, &errorData)
		errDesc := "Invalid refresh token"
		if desc, ok := errorData["error_description"].(string); ok {
			errDesc = desc
		}
		return nil, NewTokenExpiredError(fmt.Sprintf("Refresh token expired or invalid: %s", errDesc))
	case resp.StatusCode == 429:
		return nil, NewTokenError("Rate limited during token refresh. Please try again later.", "")
	case resp.StatusCode >= 500:
		return nil, NewTokenError(fmt.Sprintf("Auth server temporarily unavailable (HTTP %d)", resp.StatusCode), "")
	case resp.StatusCode != 200:
		return nil, NewTokenError(fmt.Sprintf("Token refresh failed: HTTP %d", resp.StatusCode), "")
	}

	var newTokenData TokenData
	if err := json.Unmarshal(body, &newTokenData); err != nil {
		return nil, NewTokenError(fmt.Sprintf("Token refresh failed: invalid response: %v", err), "")
	}

	return &newTokenData, nil
}

func mergeTokenData(old, new *TokenData) *TokenData {
	merged := *old
	if new.AccessToken != "" {
		merged.AccessToken = new.AccessToken
	}
	if new.RefreshToken != "" {
		merged.RefreshToken = new.RefreshToken
	}
	if new.TokenType != "" {
		merged.TokenType = new.TokenType
	}
	if new.ExpiresIn != 0 {
		merged.ExpiresIn = new.ExpiresIn
	}
	if new.Scope != "" {
		merged.Scope = new.Scope
	}
	return &merged
}

// LoadUserToken loads a user token from storage.
func LoadUserToken() (string, error) {
	storage := GetTokenStorage()
	tokenData, err := storage.LoadToken()
	if err != nil {
		return "", nil
	}
	if tokenData == nil {
		return "", nil
	}
	return tokenData.AccessToken, nil
}

// SaveUserToken saves a user token to storage.
func SaveUserToken(token string) error {
	storage := GetTokenStorage()
	return storage.SaveToken(&TokenData{AccessToken: token})
}

// SaveUserTokenData saves full token data to storage.
func SaveUserTokenData(tokenData *TokenData) error {
	storage := GetTokenStorage()
	return storage.SaveToken(tokenData)
}

// ClearCachedToken clears the cached token.
func ClearCachedToken() error {
	storage := GetTokenStorage()
	return storage.ClearToken()
}

// IsTokenActive checks if the cached token is active without attempting refresh.
func IsTokenActive(ctx context.Context) bool {
	storage := GetTokenStorage()
	tokenData, err := storage.LoadToken()
	if err != nil || tokenData == nil || tokenData.AccessToken == "" {
		return false
	}

	cfg := GetStaticConfig()
	oidcConfig, err := GetOidcConfig(ctx, cfg.AuthIssuer)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcConfig.UserinfoEndpoint, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from OIDC discovery userinfo_endpoint
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// IsTokenActiveWithRefresh checks if the cached token is active, attempting refresh if needed.
func IsTokenActiveWithRefresh(ctx context.Context) bool {
	manager := NewTokenManager()
	_, err := manager.GetValidToken(ctx)
	return err == nil
}

// ValidateToken validates a token using local verification with remote fallback.
func ValidateToken(ctx context.Context, token string) bool {
	cfg := GetStaticConfig()

	result := VerifyJWTLocal(ctx, token, cfg.AuthIssuer, cfg.APIAudience)
	if result == JWTValid {
		return true
	}

	if result == JWTInvalid {
		// Try remote validation
		oidcConfig, err := GetOidcConfig(ctx, cfg.AuthIssuer)
		if err != nil {
			return false
		}

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcConfig.UserinfoEndpoint, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from OIDC discovery userinfo_endpoint
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		return resp.StatusCode == http.StatusOK
	}

	return false
}
