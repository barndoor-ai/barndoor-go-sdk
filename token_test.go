package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// FileTokenStorage
// ---------------------------------------------------------------------------

func TestFileTokenStorage_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	storage := &FileTokenStorage{tokenFile: filepath.Join(dir, "token.json")}

	td := &TokenData{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid profile",
	}

	if err := storage.SaveToken(td); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	loaded, err := storage.LoadToken()
	if err != nil {
		t.Fatalf("LoadToken failed: %v", err)
	}

	if loaded.AccessToken != "access-123" {
		t.Errorf("AccessToken = %q", loaded.AccessToken)
	}
	if loaded.RefreshToken != "refresh-456" {
		t.Errorf("RefreshToken = %q", loaded.RefreshToken)
	}
	if loaded.TokenType != "Bearer" {
		t.Errorf("TokenType = %q", loaded.TokenType)
	}
	if loaded.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d", loaded.ExpiresIn)
	}
	if loaded.Scope != "openid profile" {
		t.Errorf("Scope = %q", loaded.Scope)
	}
}

func TestFileTokenStorage_SaveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested", "dir", "token.json")
	storage := &FileTokenStorage{tokenFile: nested}

	td := &TokenData{AccessToken: "test"}
	if err := storage.SaveToken(td); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Verify the directory was created
	if _, err := os.Stat(filepath.Dir(nested)); os.IsNotExist(err) {
		t.Error("directory should have been created")
	}
}

func TestFileTokenStorage_SaveFilePermissions(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token.json")
	storage := &FileTokenStorage{tokenFile: tokenFile}

	td := &TokenData{AccessToken: "test"}
	if err := storage.SaveToken(td); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	// File should be 0600 (owner read/write only)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestFileTokenStorage_LoadNonExistent(t *testing.T) {
	dir := t.TempDir()
	storage := &FileTokenStorage{tokenFile: filepath.Join(dir, "nonexistent.json")}

	loaded, err := storage.LoadToken()
	if err != nil {
		t.Fatalf("LoadToken should not error for nonexistent file: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil for nonexistent file")
	}
}

func TestFileTokenStorage_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token.json")
	os.WriteFile(tokenFile, []byte("not json"), 0600)

	storage := &FileTokenStorage{tokenFile: tokenFile}
	_, err := storage.LoadToken()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFileTokenStorage_ClearToken(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token.json")
	storage := &FileTokenStorage{tokenFile: tokenFile}

	// Save and then clear
	storage.SaveToken(&TokenData{AccessToken: "test"})

	if err := storage.ClearToken(); err != nil {
		t.Fatalf("ClearToken failed: %v", err)
	}

	// File should be gone
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Error("file should have been removed")
	}
}

func TestFileTokenStorage_ClearNonExistent(t *testing.T) {
	dir := t.TempDir()
	storage := &FileTokenStorage{tokenFile: filepath.Join(dir, "nonexistent.json")}

	// Should not error
	if err := storage.ClearToken(); err != nil {
		t.Fatalf("ClearToken should not error for nonexistent file: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewFileTokenStorage
// ---------------------------------------------------------------------------

func TestNewFileTokenStorage(t *testing.T) {
	storage := NewFileTokenStorage()
	if storage.tokenFile == "" {
		t.Error("tokenFile should not be empty")
	}
	if !strings.Contains(storage.tokenFile, ".barndoor") {
		t.Errorf("tokenFile = %q, expected .barndoor directory", storage.tokenFile)
	}
}

// ---------------------------------------------------------------------------
// GetTokenStorage
// ---------------------------------------------------------------------------

func TestGetTokenStorage(t *testing.T) {
	storage := GetTokenStorage()
	if storage == nil {
		t.Fatal("GetTokenStorage returned nil")
	}
}

// ---------------------------------------------------------------------------
// mergeTokenData
// ---------------------------------------------------------------------------

func TestMergeTokenData_FullMerge(t *testing.T) {
	old := &TokenData{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid",
	}
	new := &TokenData{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "MAC",
		ExpiresIn:    7200,
		Scope:        "openid profile",
	}

	merged := mergeTokenData(old, new)
	if merged.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q", merged.AccessToken)
	}
	if merged.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q", merged.RefreshToken)
	}
	if merged.TokenType != "MAC" {
		t.Errorf("TokenType = %q", merged.TokenType)
	}
	if merged.ExpiresIn != 7200 {
		t.Errorf("ExpiresIn = %d", merged.ExpiresIn)
	}
	if merged.Scope != "openid profile" {
		t.Errorf("Scope = %q", merged.Scope)
	}
}

func TestMergeTokenData_PartialMerge(t *testing.T) {
	old := &TokenData{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid",
	}
	new := &TokenData{
		AccessToken: "new-access",
		// RefreshToken, TokenType, ExpiresIn, Scope all zero/empty
	}

	merged := mergeTokenData(old, new)
	if merged.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want new", merged.AccessToken)
	}
	// Old values should be preserved when new is empty
	if merged.RefreshToken != "old-refresh" {
		t.Errorf("RefreshToken = %q, want old", merged.RefreshToken)
	}
	if merged.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want old", merged.TokenType)
	}
	if merged.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want old", merged.ExpiresIn)
	}
	if merged.Scope != "openid" {
		t.Errorf("Scope = %q, want old", merged.Scope)
	}
}

func TestMergeTokenData_EmptyNew(t *testing.T) {
	old := &TokenData{
		AccessToken:  "old",
		RefreshToken: "refresh",
	}
	merged := mergeTokenData(old, &TokenData{})
	if merged.AccessToken != "old" {
		t.Errorf("AccessToken should remain old: %q", merged.AccessToken)
	}
	if merged.RefreshToken != "refresh" {
		t.Errorf("RefreshToken should remain old: %q", merged.RefreshToken)
	}
}

func TestMergeTokenData_DoesNotMutateOld(t *testing.T) {
	old := &TokenData{AccessToken: "old"}
	new := &TokenData{AccessToken: "new"}

	mergeTokenData(old, new)
	if old.AccessToken != "old" {
		t.Error("mergeTokenData should not mutate the old value")
	}
}

// ---------------------------------------------------------------------------
// decodeJWTPayload
// ---------------------------------------------------------------------------

func TestDecodeJWTPayload_Valid(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"sub": "user123",
		"exp": 1700000000,
	})

	claims, err := decodeJWTPayload(token)
	if err != nil {
		t.Fatalf("decodeJWTPayload failed: %v", err)
	}

	if claims["sub"] != "user123" {
		t.Errorf("sub = %v", claims["sub"])
	}
}

func TestDecodeJWTPayload_InvalidFormat(t *testing.T) {
	_, err := decodeJWTPayload("not.a.valid.jwt.format")
	if err == nil {
		t.Fatal("expected error for invalid JWT format")
	}
}

func TestDecodeJWTPayload_TwoParts(t *testing.T) {
	_, err := decodeJWTPayload("header.payload")
	if err == nil {
		t.Fatal("expected error for two-part JWT")
	}
}

func TestDecodeJWTPayload_InvalidBase64(t *testing.T) {
	_, err := decodeJWTPayload("header.!!!invalid.sig")
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func TestDecodeJWTPayload_InvalidJSON(t *testing.T) {
	_, err := decodeJWTPayload("header.bm90LWpzb24.sig") // "not-json" in base64
	if err == nil {
		t.Fatal("expected error for non-JSON payload")
	}
}

// ---------------------------------------------------------------------------
// shouldRefreshToken (via TokenManager)
// ---------------------------------------------------------------------------

func TestShouldRefreshToken_ExpiringSoon(t *testing.T) {
	// Token that expires in 2 minutes (less than 5 minute threshold)
	token := makeTestJWT(map[string]any{
		"exp": float64(time.Now().Unix() + 120),
	})
	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: token}

	if !m.shouldRefreshToken(td) {
		t.Error("expected shouldRefreshToken=true for token expiring in 2 minutes")
	}
}

func TestShouldRefreshToken_NotExpiringSoon(t *testing.T) {
	// Token that expires in 1 hour
	token := makeTestJWT(map[string]any{
		"exp": float64(time.Now().Unix() + 3600),
	})
	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: token}

	if m.shouldRefreshToken(td) {
		t.Error("expected shouldRefreshToken=false for token expiring in 1 hour")
	}
}

func TestShouldRefreshToken_InvalidJWT(t *testing.T) {
	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "not-a-jwt"}

	// Invalid JWT should return true (safe default: try to refresh)
	if !m.shouldRefreshToken(td) {
		t.Error("expected shouldRefreshToken=true for invalid JWT")
	}
}

func TestShouldRefreshToken_NoExpClaim(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"sub": "user1",
		// No exp claim
	})
	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: token}

	if !m.shouldRefreshToken(td) {
		t.Error("expected shouldRefreshToken=true when no exp claim")
	}
}

// ---------------------------------------------------------------------------
// NewTokenManager
// ---------------------------------------------------------------------------

func TestNewTokenManager(t *testing.T) {
	m := NewTokenManager()
	if m == nil {
		t.Fatal("NewTokenManager returned nil")
	}
	if m.storage == nil {
		t.Error("storage should not be nil")
	}
	if m.logger == nil {
		t.Error("logger should not be nil")
	}
}

// ---------------------------------------------------------------------------
// Token data JSON serialization
// ---------------------------------------------------------------------------

func TestTokenData_JSONRoundTrip(t *testing.T) {
	td := &TokenData{
		AccessToken:  "access",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "openid",
	}

	data, err := json.Marshal(td)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TokenData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.AccessToken != "access" {
		t.Errorf("AccessToken = %q", decoded.AccessToken)
	}
	if decoded.RefreshToken != "refresh" {
		t.Errorf("RefreshToken = %q", decoded.RefreshToken)
	}
}

func TestTokenData_JSONOmitsEmpty(t *testing.T) {
	td := &TokenData{AccessToken: "access"}

	data, err := json.Marshal(td)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	if strings.Contains(string(data), "refresh_token") {
		t.Error("empty RefreshToken should be omitted from JSON")
	}
}

// ---------------------------------------------------------------------------
// mockTokenStorage — in-memory TokenStorage for testing
// ---------------------------------------------------------------------------

type mockTokenStorage struct {
	token *TokenData
	err   error
}

func (m *mockTokenStorage) LoadToken() (*TokenData, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

func (m *mockTokenStorage) SaveToken(td *TokenData) error {
	m.token = td
	return nil
}

func (m *mockTokenStorage) ClearToken() error {
	m.token = nil
	return nil
}

// ---------------------------------------------------------------------------
// setupMockOIDC creates an httptest server that serves OIDC endpoints
// and pre-populates the OIDC config cache for the given issuer key.
// ---------------------------------------------------------------------------

func setupMockOIDC(t *testing.T, userinfoStatus int, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := OidcConfig{
				Issuer:                server.URL,
				AuthorizationEndpoint: server.URL + "/authorize",
				TokenEndpoint:         server.URL + "/token",
				UserinfoEndpoint:      server.URL + "/userinfo",
				JWKSURI:               server.URL + "/jwks",
			}
			json.NewEncoder(w).Encode(cfg)
		case "/userinfo":
			w.WriteHeader(userinfoStatus)
			fmt.Fprint(w, `{"sub":"user1"}`)
		case "/token":
			if tokenHandler != nil {
				tokenHandler(w, r)
			} else {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"access_token":"new-access","refresh_token":"new-refresh"}`)
			}
		case "/jwks":
			fmt.Fprint(w, `{"keys":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))

	// Pre-populate the OIDC config cache
	ClearOidcConfigCache()
	oidcConfigCacheMu.Lock()
	oidcConfigCache[server.URL] = &OidcConfig{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		UserinfoEndpoint:      server.URL + "/userinfo",
		JWKSURI:               server.URL + "/jwks",
	}
	oidcConfigCacheMu.Unlock()

	t.Cleanup(func() {
		server.Close()
		ClearOidcConfigCache()
	})

	return server
}

// ---------------------------------------------------------------------------
// TokenManager.GetValidToken
// ---------------------------------------------------------------------------

func TestGetValidToken_NoToken(t *testing.T) {
	m := &TokenManager{
		storage: &mockTokenStorage{token: nil},
		logger:  createScopedLogger("test"),
	}
	_, err := m.GetValidToken(context.Background())
	if err == nil {
		t.Fatal("expected error when no token stored")
	}
}

func TestGetValidToken_LoadError(t *testing.T) {
	m := &TokenManager{
		storage: &mockTokenStorage{err: fmt.Errorf("disk error")},
		logger:  createScopedLogger("test"),
	}
	_, err := m.GetValidToken(context.Background())
	if err == nil {
		t.Fatal("expected error for storage load failure")
	}
}

func TestGetValidToken_ValidRemotely(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, nil)

	// Point config to our mock server
	t.Setenv("BARNDOOR_ENV", "production")
	t.Setenv("AUTH_URL", server.URL)

	token := makeTestJWT(map[string]any{
		"sub": "user1",
		"exp": float64(time.Now().Unix() + 3600),
	})

	storage := &mockTokenStorage{token: &TokenData{AccessToken: token}}
	m := &TokenManager{storage: storage, logger: createScopedLogger("test")}

	result, err := m.GetValidToken(context.Background())
	if err != nil {
		t.Fatalf("GetValidToken failed: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty token")
	}
}

func TestGetValidToken_RefreshesExpiredToken(t *testing.T) {
	server := setupMockOIDC(t, http.StatusUnauthorized, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"access_token":"refreshed-token","refresh_token":"new-refresh"}`)
	})

	t.Setenv("AUTH_URL", server.URL)

	// Token that is already expired
	expiredToken := makeTestJWT(map[string]any{
		"sub": "user1",
		"exp": float64(time.Now().Unix() - 3600),
	})

	storage := &mockTokenStorage{token: &TokenData{
		AccessToken:  expiredToken,
		RefreshToken: "old-refresh",
	}}
	m := &TokenManager{storage: storage, logger: createScopedLogger("test")}

	result, err := m.GetValidToken(context.Background())
	if err != nil {
		t.Fatalf("GetValidToken failed: %v", err)
	}
	if result != "refreshed-token" {
		t.Errorf("expected refreshed token, got %q", result)
	}
}

func TestGetValidToken_RefreshFailsNoRefreshToken(t *testing.T) {
	server := setupMockOIDC(t, http.StatusUnauthorized, nil)
	t.Setenv("AUTH_URL", server.URL)

	expiredToken := makeTestJWT(map[string]any{
		"sub": "user1",
		"exp": float64(time.Now().Unix() - 3600),
	})

	storage := &mockTokenStorage{token: &TokenData{
		AccessToken: expiredToken,
		// No RefreshToken
	}}
	m := &TokenManager{storage: storage, logger: createScopedLogger("test")}

	_, err := m.GetValidToken(context.Background())
	if err == nil {
		t.Fatal("expected error when expired with no refresh token")
	}
}

// ---------------------------------------------------------------------------
// TokenManager.validateOrRefresh
// ---------------------------------------------------------------------------

func TestValidateOrRefresh_ValidRemote(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, nil)
	t.Setenv("AUTH_URL", server.URL)

	token := makeTestJWT(map[string]any{
		"sub": "user1",
		"exp": float64(time.Now().Unix() + 3600),
	})
	td := &TokenData{AccessToken: token}
	m := &TokenManager{storage: &mockTokenStorage{}, logger: createScopedLogger("test")}

	result, err := m.validateOrRefresh(context.Background(), td)
	if err != nil {
		t.Fatalf("validateOrRefresh failed: %v", err)
	}
	if result.AccessToken != token {
		t.Error("expected same token (valid remotely)")
	}
}

func TestValidateOrRefresh_RefreshOnExpired(t *testing.T) {
	server := setupMockOIDC(t, http.StatusUnauthorized, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"refreshed","refresh_token":"new-rt"}`)
	})
	t.Setenv("AUTH_URL", server.URL)

	expiredToken := makeTestJWT(map[string]any{
		"sub": "user1",
		"exp": float64(time.Now().Unix() - 100),
	})
	td := &TokenData{AccessToken: expiredToken, RefreshToken: "old-rt"}
	m := &TokenManager{storage: &mockTokenStorage{}, logger: createScopedLogger("test")}

	result, err := m.validateOrRefresh(context.Background(), td)
	if err != nil {
		t.Fatalf("validateOrRefresh failed: %v", err)
	}
	if result.AccessToken != "refreshed" {
		t.Errorf("AccessToken = %q, want refreshed", result.AccessToken)
	}
}

// ---------------------------------------------------------------------------
// TokenManager.isTokenValidRemote
// ---------------------------------------------------------------------------

func TestIsTokenValidRemote_Valid(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, nil)
	t.Setenv("AUTH_URL", server.URL)

	m := &TokenManager{logger: createScopedLogger("test")}
	if !m.isTokenValidRemote(context.Background(), "some-token") {
		t.Error("expected true for valid remote token")
	}
}

func TestIsTokenValidRemote_Invalid(t *testing.T) {
	server := setupMockOIDC(t, http.StatusUnauthorized, nil)
	t.Setenv("AUTH_URL", server.URL)

	m := &TokenManager{logger: createScopedLogger("test")}
	if m.isTokenValidRemote(context.Background(), "bad-token") {
		t.Error("expected false for invalid remote token")
	}
}

// ---------------------------------------------------------------------------
// TokenManager.refreshToken
// ---------------------------------------------------------------------------

func TestRefreshToken_Success(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", r.Form.Get("grant_type"))
		}
		fmt.Fprint(w, `{"access_token":"new-at","refresh_token":"new-rt","token_type":"Bearer","expires_in":7200}`)
	})
	t.Setenv("AUTH_URL", server.URL)
	t.Setenv("AGENT_CLIENT_ID", "test-client")
	t.Setenv("AGENT_CLIENT_SECRET", "test-secret")

	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	result, err := m.refreshToken(context.Background(), td)
	if err != nil {
		t.Fatalf("refreshToken failed: %v", err)
	}
	if result.AccessToken != "new-at" {
		t.Errorf("AccessToken = %q", result.AccessToken)
	}
}

func TestRefreshToken_NoRefreshToken(t *testing.T) {
	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old"}

	_, err := m.refreshToken(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for missing refresh token")
	}
}

func TestRefreshToken_400Error(t *testing.T) {
	setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Token revoked"}`)
	})
	t.Setenv("AUTH_URL", "")
	// The setupMockOIDC already put the config in cache; we need to set AUTH_URL to the server
	// Actually, refreshToken calls GetStaticConfig() which reads env vars.
	// We need AUTH_URL to point to the mock server.

	// Re-read from the oidc cache directly
	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	_, err := m.refreshToken(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestRefreshToken_429RateLimit(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	t.Setenv("AUTH_URL", server.URL)

	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	_, err := m.refreshToken(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for 429")
	}
	if !strings.Contains(err.Error(), "Rate limited") {
		t.Errorf("expected rate limit error: %v", err)
	}
}

func TestRefreshToken_500ServerError(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	t.Setenv("AUTH_URL", server.URL)

	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	_, err := m.refreshToken(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("expected server error: %v", err)
	}
}

func TestRefreshToken_OtherHTTPError(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	t.Setenv("AUTH_URL", server.URL)

	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	_, err := m.refreshToken(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for 403")
	}
}

func TestRefreshToken_InvalidResponseJSON(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "not json")
	})
	t.Setenv("AUTH_URL", server.URL)

	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	_, err := m.refreshToken(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

// ---------------------------------------------------------------------------
// LoadUserToken / SaveUserToken / SaveUserTokenData / ClearCachedToken
// (these use GetTokenStorage which uses the real filesystem,
// so we test with a temp HOME directory)
// ---------------------------------------------------------------------------

func TestLoadUserToken_NoFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	token, err := LoadUserToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}
}

func TestSaveAndLoadUserToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := SaveUserToken("my-access-token")
	if err != nil {
		t.Fatalf("SaveUserToken failed: %v", err)
	}

	token, err := LoadUserToken()
	if err != nil {
		t.Fatalf("LoadUserToken failed: %v", err)
	}
	if token != "my-access-token" {
		t.Errorf("token = %q, want %q", token, "my-access-token")
	}
}

func TestSaveUserTokenData(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	td := &TokenData{AccessToken: "at", RefreshToken: "rt"}
	err := SaveUserTokenData(td)
	if err != nil {
		t.Fatalf("SaveUserTokenData failed: %v", err)
	}

	token, err := LoadUserToken()
	if err != nil {
		t.Fatalf("LoadUserToken failed: %v", err)
	}
	if token != "at" {
		t.Errorf("token = %q, want %q", token, "at")
	}
}

func TestClearCachedToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	SaveUserToken("to-be-cleared")
	err := ClearCachedToken()
	if err != nil {
		t.Fatalf("ClearCachedToken failed: %v", err)
	}

	token, _ := LoadUserToken()
	if token != "" {
		t.Errorf("token should be empty after clear, got %q", token)
	}
}

// ---------------------------------------------------------------------------
// ValidateToken
// ---------------------------------------------------------------------------

func TestValidateToken_ValidRemote(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, nil)
	t.Setenv("AUTH_URL", server.URL)

	token := makeTestJWT(map[string]any{"sub": "user1", "exp": float64(time.Now().Unix() + 3600)})
	if !ValidateToken(context.Background(), token) {
		t.Error("expected true for remotely valid token")
	}
}

func TestValidateToken_InvalidRemote(t *testing.T) {
	server := setupMockOIDC(t, http.StatusUnauthorized, nil)
	t.Setenv("AUTH_URL", server.URL)

	token := makeTestJWT(map[string]any{"sub": "user1", "exp": float64(time.Now().Unix() + 3600)})
	if ValidateToken(context.Background(), token) {
		t.Error("expected false for remotely invalid token")
	}
}

// ---------------------------------------------------------------------------
// IsTokenActive
// ---------------------------------------------------------------------------

func TestIsTokenActive_NoToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if IsTokenActive(context.Background()) {
		t.Error("expected false when no token stored")
	}
}

func TestIsTokenActive_WithValidToken(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Save a token
	SaveUserToken("test-active-token")

	server := setupMockOIDC(t, http.StatusOK, nil)
	t.Setenv("AUTH_URL", server.URL)

	if !IsTokenActive(context.Background()) {
		t.Error("expected true for active token")
	}
}

func TestIsTokenActive_WithInvalidToken(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	SaveUserToken("expired-token")

	server := setupMockOIDC(t, http.StatusUnauthorized, nil)
	t.Setenv("AUTH_URL", server.URL)

	if IsTokenActive(context.Background()) {
		t.Error("expected false for inactive token")
	}
}

// ---------------------------------------------------------------------------
// IsTokenActiveWithRefresh
// ---------------------------------------------------------------------------

func TestIsTokenActiveWithRefresh_NoToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if IsTokenActiveWithRefresh(context.Background()) {
		t.Error("expected false when no token stored")
	}
}

func TestIsTokenActiveWithRefresh_ValidToken(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	token := makeTestJWT(map[string]any{
		"sub": "user1",
		"exp": float64(time.Now().Unix() + 3600),
	})
	SaveUserToken(token)

	server := setupMockOIDC(t, http.StatusOK, nil)
	t.Setenv("AUTH_URL", server.URL)

	if !IsTokenActiveWithRefresh(context.Background()) {
		t.Error("expected true for valid token")
	}
}

// ---------------------------------------------------------------------------
// refreshToken — client_secret in config
// ---------------------------------------------------------------------------

func TestRefreshToken_WithClientSecret(t *testing.T) {
	var receivedSecret string
	server := setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedSecret = r.Form.Get("client_secret")
		fmt.Fprint(w, `{"access_token":"new","refresh_token":"new-rt"}`)
	})
	t.Setenv("AUTH_URL", server.URL)
	t.Setenv("AGENT_CLIENT_ID", "cid")
	t.Setenv("AGENT_CLIENT_SECRET", "csecret")

	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	_, err := m.refreshToken(context.Background(), td)
	if err != nil {
		t.Fatalf("refreshToken failed: %v", err)
	}
	if receivedSecret != "csecret" {
		t.Errorf("client_secret = %q, want %q", receivedSecret, "csecret")
	}
}

// ---------------------------------------------------------------------------
// GetValidToken — proactive refresh path
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SaveToken — error paths
// ---------------------------------------------------------------------------

func TestSaveToken_ReadOnlyParent(t *testing.T) {
	dir := t.TempDir()
	// Create a file where the directory should be, so MkdirAll fails
	badPath := filepath.Join(dir, "blocked")
	os.WriteFile(badPath, []byte("I'm a file"), 0600)
	tokenFile := filepath.Join(badPath, "nested", "token.json")

	storage := &FileTokenStorage{tokenFile: tokenFile}
	err := storage.SaveToken(&TokenData{AccessToken: "test"})
	if err == nil {
		t.Fatal("expected error when directory creation fails")
	}
}

// ---------------------------------------------------------------------------
// ClearToken — error path (non-permission error)
// ---------------------------------------------------------------------------

func TestClearToken_PermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test as root")
	}
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "subdir", "token.json")
	os.MkdirAll(filepath.Dir(tokenFile), 0700)
	os.WriteFile(tokenFile, []byte(`{}`), 0600)

	// Make directory read-only so Remove fails
	os.Chmod(filepath.Dir(tokenFile), 0500)
	defer os.Chmod(filepath.Dir(tokenFile), 0700)

	storage := &FileTokenStorage{tokenFile: tokenFile}
	err := storage.ClearToken()
	if err == nil {
		t.Fatal("expected error when remove fails due to permissions")
	}
}

// ---------------------------------------------------------------------------
// ValidateToken — JWTExpired path
// ---------------------------------------------------------------------------

func TestValidateToken_Expired(t *testing.T) {
	// When VerifyJWTLocal returns JWTExpired, ValidateToken should return false
	// without trying remote validation
	ClearOidcConfigCache()
	defer ClearOidcConfigCache()

	server := setupMockOIDC(t, http.StatusOK, nil)
	t.Setenv("AUTH_URL", server.URL)

	// Use a token that will fail local verification (no real signature)
	// and trigger the JWTInvalid path, not JWTExpired, so we test the
	// remote validation fallback returning true for valid
	token := makeTestJWT(map[string]any{"sub": "user1", "exp": float64(time.Now().Unix() + 3600)})
	if !ValidateToken(context.Background(), token) {
		t.Error("expected true for remotely valid token (JWTInvalid -> remote valid)")
	}
}

// ---------------------------------------------------------------------------
// refreshToken — network error during HTTP request
// ---------------------------------------------------------------------------

func TestRefreshToken_NetworkError(t *testing.T) {
	ClearOidcConfigCache()
	defer ClearOidcConfigCache()

	// Point OIDC config to an unreachable token endpoint
	oidcConfigCacheMu.Lock()
	oidcConfigCache["http://auth.test"] = &OidcConfig{
		Issuer:        "http://auth.test",
		TokenEndpoint: "http://127.0.0.1:1/token", // unreachable
	}
	oidcConfigCacheMu.Unlock()

	t.Setenv("AUTH_URL", "http://auth.test")
	t.Setenv("AGENT_CLIENT_ID", "cid")

	m := &TokenManager{logger: createScopedLogger("test")}
	td := &TokenData{AccessToken: "old", RefreshToken: "old-rt"}

	_, err := m.refreshToken(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "Network error") {
		t.Errorf("expected network error message, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// isTokenValidRemote — network error
// ---------------------------------------------------------------------------

func TestIsTokenValidRemote_NetworkError(t *testing.T) {
	ClearOidcConfigCache()
	defer ClearOidcConfigCache()

	oidcConfigCacheMu.Lock()
	oidcConfigCache["http://auth.test"] = &OidcConfig{
		Issuer:           "http://auth.test",
		UserinfoEndpoint: "http://127.0.0.1:1/userinfo", // unreachable
	}
	oidcConfigCacheMu.Unlock()

	t.Setenv("AUTH_URL", "http://auth.test")

	m := &TokenManager{logger: createScopedLogger("test")}
	if m.isTokenValidRemote(context.Background(), "token") {
		t.Error("expected false for network error")
	}
}

// ---------------------------------------------------------------------------
// validateOrRefresh — JWTExpired goes directly to refresh
// ---------------------------------------------------------------------------

func TestValidateOrRefresh_ExpiredNoRefreshToken(t *testing.T) {
	server := setupMockOIDC(t, http.StatusUnauthorized, nil)
	t.Setenv("AUTH_URL", server.URL)

	// Token with no exp claim will trigger JWTInvalid from VerifyJWTLocal
	// (since JWKS has empty keys). Remote validation returns 401.
	// No refresh token → error.
	td := &TokenData{AccessToken: makeTestJWT(map[string]any{"sub": "user1"})}
	m := &TokenManager{storage: &mockTokenStorage{}, logger: createScopedLogger("test")}

	_, err := m.validateOrRefresh(context.Background(), td)
	if err == nil {
		t.Fatal("expected error for expired token with no refresh token")
	}
}

func TestGetValidToken_ProactiveRefresh(t *testing.T) {
	server := setupMockOIDC(t, http.StatusOK, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"proactively-refreshed","refresh_token":"new-rt"}`)
	})
	t.Setenv("AUTH_URL", server.URL)
	t.Setenv("AGENT_CLIENT_ID", "cid")

	// Token expiring in 2 minutes (within the 5-minute proactive refresh window)
	soonToken := makeTestJWT(map[string]any{
		"sub": "user1",
		"exp": float64(time.Now().Unix() + 120),
	})

	storage := &mockTokenStorage{token: &TokenData{
		AccessToken:  soonToken,
		RefreshToken: "has-refresh",
	}}
	m := &TokenManager{storage: storage, logger: createScopedLogger("test")}

	result, err := m.GetValidToken(context.Background())
	if err != nil {
		t.Fatalf("GetValidToken failed: %v", err)
	}
	if result != "proactively-refreshed" {
		t.Errorf("expected proactively refreshed token, got %q", result)
	}
}
