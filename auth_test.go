package barndoor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// oidcFallback
// ---------------------------------------------------------------------------

func TestOidcFallback_KeycloakIssuer(t *testing.T) {
	issuer := "https://auth.trial.barndoor.ai/realms/barndoor-local"
	logger := createScopedLogger("test")

	cfg := oidcFallback(issuer, logger)

	if cfg.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", cfg.Issuer, issuer)
	}
	wantAuth := issuer + "/protocol/openid-connect/auth"
	if cfg.AuthorizationEndpoint != wantAuth {
		t.Errorf("AuthorizationEndpoint = %q, want %q", cfg.AuthorizationEndpoint, wantAuth)
	}
	wantToken := issuer + "/protocol/openid-connect/token"
	if cfg.TokenEndpoint != wantToken {
		t.Errorf("TokenEndpoint = %q, want %q", cfg.TokenEndpoint, wantToken)
	}
	wantUserinfo := issuer + "/protocol/openid-connect/userinfo"
	if cfg.UserinfoEndpoint != wantUserinfo {
		t.Errorf("UserinfoEndpoint = %q, want %q", cfg.UserinfoEndpoint, wantUserinfo)
	}
	wantJWKS := issuer + "/protocol/openid-connect/certs"
	if cfg.JWKSURI != wantJWKS {
		t.Errorf("JWKSURI = %q, want %q", cfg.JWKSURI, wantJWKS)
	}
}

func TestOidcFallback_Auth0Issuer(t *testing.T) {
	issuer := "https://auth.barndoor.ai"
	logger := createScopedLogger("test")

	cfg := oidcFallback(issuer, logger)

	if cfg.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", cfg.Issuer, issuer)
	}
	wantAuth := issuer + "/authorize"
	if cfg.AuthorizationEndpoint != wantAuth {
		t.Errorf("AuthorizationEndpoint = %q, want %q", cfg.AuthorizationEndpoint, wantAuth)
	}
	wantToken := issuer + "/oauth/token"
	if cfg.TokenEndpoint != wantToken {
		t.Errorf("TokenEndpoint = %q, want %q", cfg.TokenEndpoint, wantToken)
	}
	wantUserinfo := issuer + "/userinfo"
	if cfg.UserinfoEndpoint != wantUserinfo {
		t.Errorf("UserinfoEndpoint = %q, want %q", cfg.UserinfoEndpoint, wantUserinfo)
	}
	wantJWKS := issuer + "/.well-known/jwks.json"
	if cfg.JWKSURI != wantJWKS {
		t.Errorf("JWKSURI = %q, want %q", cfg.JWKSURI, wantJWKS)
	}
}

func TestOidcFallback_AllAuthConfigIssuers(t *testing.T) {
	logger := createScopedLogger("test")

	for envName, envCfg := range AuthConfig {
		t.Run(envName, func(t *testing.T) {
			issuer := strings.TrimRight(envCfg.Issuer, "/")
			cfg := oidcFallback(issuer, logger)

			isKeycloak := strings.Contains(issuer, "/realms/")
			if isKeycloak {
				if !strings.HasSuffix(cfg.AuthorizationEndpoint, "/protocol/openid-connect/auth") {
					t.Errorf("Keycloak env %s: AuthorizationEndpoint = %q, expected Keycloak path", envName, cfg.AuthorizationEndpoint)
				}
				if !strings.HasSuffix(cfg.TokenEndpoint, "/protocol/openid-connect/token") {
					t.Errorf("Keycloak env %s: TokenEndpoint = %q, expected Keycloak path", envName, cfg.TokenEndpoint)
				}
			} else {
				if !strings.HasSuffix(cfg.AuthorizationEndpoint, "/authorize") {
					t.Errorf("Auth0 env %s: AuthorizationEndpoint = %q, expected Auth0 path", envName, cfg.AuthorizationEndpoint)
				}
				if !strings.HasSuffix(cfg.TokenEndpoint, "/oauth/token") {
					t.Errorf("Auth0 env %s: TokenEndpoint = %q, expected Auth0 path", envName, cfg.TokenEndpoint)
				}
			}
		})
	}
}

func TestOidcFallback_TrailingSlashStripped(t *testing.T) {
	logger := createScopedLogger("test")

	// The caller (GetOidcConfig) should strip trailing slashes before calling oidcFallback.
	// Verify the fallback doesn't produce double slashes if a trailing slash is present.
	issuer := "https://auth.barndoor.ai/"
	cfg := oidcFallback(issuer, logger)

	if strings.Contains(cfg.AuthorizationEndpoint, "//authorize") {
		t.Errorf("AuthorizationEndpoint has double slash: %q", cfg.AuthorizationEndpoint)
	}
}

// ---------------------------------------------------------------------------
// GetOidcConfig
// ---------------------------------------------------------------------------

func TestGetOidcConfig_Discovery(t *testing.T) {
	ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		cfg := OidcConfig{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/custom/authorize",
			TokenEndpoint:         server.URL + "/custom/token",
			UserinfoEndpoint:      server.URL + "/custom/userinfo",
			JWKSURI:               server.URL + "/custom/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	}))
	defer server.Close()

	ctx := context.Background()
	cfg, err := GetOidcConfig(ctx, server.URL)
	if err != nil {
		t.Fatalf("GetOidcConfig failed: %v", err)
	}

	if cfg.AuthorizationEndpoint != server.URL+"/custom/authorize" {
		t.Errorf("AuthorizationEndpoint = %q, want %q", cfg.AuthorizationEndpoint, server.URL+"/custom/authorize")
	}
	if cfg.TokenEndpoint != server.URL+"/custom/token" {
		t.Errorf("TokenEndpoint = %q, want %q", cfg.TokenEndpoint, server.URL+"/custom/token")
	}
}

func TestGetOidcConfig_DiscoveryCached(t *testing.T) {
	ClearOidcConfigCache()

	calls := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		cfg := OidcConfig{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	}))
	defer server.Close()

	ctx := context.Background()
	_, _ = GetOidcConfig(ctx, server.URL)
	_, _ = GetOidcConfig(ctx, server.URL)

	if calls != 1 {
		t.Errorf("Expected 1 HTTP call (cached), got %d", calls)
	}
}

func TestGetOidcConfig_FallbackOnHTTPError(t *testing.T) {
	ClearOidcConfigCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	cfg, err := GetOidcConfig(ctx, server.URL)
	if err != nil {
		t.Fatalf("GetOidcConfig should not error on fallback: %v", err)
	}

	// server.URL has no /realms/, so should get Auth0-style fallback
	wantAuth := server.URL + "/authorize"
	if cfg.AuthorizationEndpoint != wantAuth {
		t.Errorf("AuthorizationEndpoint = %q, want %q", cfg.AuthorizationEndpoint, wantAuth)
	}
}

func TestGetOidcConfig_FallbackNotCached(t *testing.T) {
	ClearOidcConfigCache()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	_, _ = GetOidcConfig(ctx, server.URL)
	_, _ = GetOidcConfig(ctx, server.URL)

	// Fallback results are not cached, so each call hits the server
	if calls != 2 {
		t.Errorf("Expected 2 HTTP calls (fallback not cached), got %d", calls)
	}
}

func TestGetOidcConfig_DiscoveryReturnsEmptyEndpoints(t *testing.T) {
	ClearOidcConfigCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return valid JSON but missing key fields
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"issuer":"https://example.com"}`)
	}))
	defer server.Close()

	ctx := context.Background()
	cfg, err := GetOidcConfig(ctx, server.URL)
	if err != nil {
		t.Fatalf("GetOidcConfig failed: %v", err)
	}

	// After the fix, incomplete discovery responses should trigger the fallback,
	// producing valid endpoints rather than empty strings.
	if cfg.AuthorizationEndpoint == "" {
		t.Error("AuthorizationEndpoint is empty — incomplete OIDC discovery should fall back to well-known endpoints")
	}
	// The test server URL has no /realms/, so Auth0-style fallback applies
	wantSuffix := "/authorize"
	if !strings.HasSuffix(cfg.AuthorizationEndpoint, wantSuffix) {
		t.Errorf("AuthorizationEndpoint = %q, want suffix %q (Auth0 fallback)", cfg.AuthorizationEndpoint, wantSuffix)
	}
}

func TestGetOidcConfig_NormalizesTrailingSlash(t *testing.T) {
	ClearOidcConfigCache()

	// Verify the discovery URL is built without double slashes
	var discoveryPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoveryPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	// Pass issuer WITH trailing slash
	_, _ = GetOidcConfig(ctx, server.URL+"/")

	if discoveryPath != "/.well-known/openid-configuration" {
		t.Errorf("Discovery path = %q, want %q", discoveryPath, "/.well-known/openid-configuration")
	}
}

// ---------------------------------------------------------------------------
// BuildAuthorizationURL
// ---------------------------------------------------------------------------

func TestBuildAuthorizationURL_WithOIDCDiscovery(t *testing.T) {
	ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/custom/authorize",
			"token_endpoint":         server.URL + "/custom/token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	}))
	defer server.Close()

	pm := NewPKCEManager()
	ctx := context.Background()

	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
		Audience:    "https://api.example.com/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	// Verify base path comes from OIDC discovery
	wantPath := "/custom/authorize"
	if parsed.Path != wantPath {
		t.Errorf("URL path = %q, want %q", parsed.Path, wantPath)
	}

	// Verify all required OAuth params are present
	q := parsed.Query()
	requiredParams := []string{
		"response_type", "client_id", "redirect_uri",
		"scope", "audience", "state",
		"code_challenge", "code_challenge_method",
	}
	for _, param := range requiredParams {
		if q.Get(param) == "" {
			t.Errorf("Missing required query param %q", param)
		}
	}

	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", q.Get("response_type"), "code")
	}
	if q.Get("client_id") != "test-client" {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), "test-client")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want %q", q.Get("code_challenge_method"), "S256")
	}
	if q.Get("scope") != "openid profile email" {
		t.Errorf("scope = %q, want %q", q.Get("scope"), "openid profile email")
	}
}

func TestBuildAuthorizationURL_FallbackKeycloak(t *testing.T) {
	ClearOidcConfigCache()

	// Use a server that returns 404 to trigger fallback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Simulate a Keycloak-style issuer by using the test server URL + /realms/
	keycloakIssuer := server.URL + "/realms/test-realm"

	pm := NewPKCEManager()
	ctx := context.Background()

	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      keycloakIssuer,
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
		Audience:    "https://api.example.com/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	wantPath := "/realms/test-realm/protocol/openid-connect/auth"
	if parsed.Path != wantPath {
		t.Errorf("Keycloak fallback: URL path = %q, want %q", parsed.Path, wantPath)
	}
}

func TestBuildAuthorizationURL_FallbackAuth0(t *testing.T) {
	ClearOidcConfigCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	pm := NewPKCEManager()
	ctx := context.Background()

	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
		Audience:    "https://api.example.com/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	wantPath := "/authorize"
	if parsed.Path != wantPath {
		t.Errorf("Auth0 fallback: URL path = %q, want %q", parsed.Path, wantPath)
	}
}

func TestBuildAuthorizationURL_AllEnvironments(t *testing.T) {
	for envName, envCfg := range AuthConfig {
		t.Run(envName, func(t *testing.T) {
			ClearOidcConfigCache()

			// We can't hit real auth servers, so we test the fallback path.
			// Create a mock server that simulates the issuer returning 404 for discovery.
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			defer mockServer.Close()

			// Replace the real issuer host with our mock server, preserving the path
			realIssuer := envCfg.Issuer
			parsedIssuer, err := url.Parse(realIssuer)
			if err != nil {
				t.Fatalf("Failed to parse issuer %q: %v", realIssuer, err)
			}

			mockIssuer := mockServer.URL + parsedIssuer.Path

			pm := NewPKCEManager()
			ctx := context.Background()

			authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
				Issuer:      mockIssuer,
				ClientID:    "test-client",
				RedirectURI: "http://localhost:52765/cb",
				Audience:    envCfg.Audience,
			})
			if err != nil {
				t.Fatalf("BuildAuthorizationURL failed for %s: %v", envName, err)
			}

			parsed, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("Failed to parse auth URL: %v", err)
			}

			isKeycloak := strings.Contains(realIssuer, "/realms/")
			if isKeycloak {
				if !strings.Contains(parsed.Path, "/protocol/openid-connect/auth") {
					t.Errorf("Keycloak env %s: expected Keycloak auth path, got %q", envName, parsed.Path)
				}
			} else {
				if !strings.HasSuffix(parsed.Path, "/authorize") {
					t.Errorf("Auth0 env %s: expected Auth0 auth path, got %q", envName, parsed.Path)
				}
			}

			// Verify audience is included
			q := parsed.Query()
			if q.Get("audience") != envCfg.Audience {
				t.Errorf("Env %s: audience = %q, want %q", envName, q.Get("audience"), envCfg.Audience)
			}
		})
	}
}

func TestBuildAuthorizationURL_DeprecatedDomain(t *testing.T) {
	pm := NewPKCEManager()
	ctx := context.Background()

	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Domain:      "auth.example.com",
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
		Audience:    "https://api.example.com/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	// Domain path always uses /authorize (Auth0-style), even for Keycloak
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	if parsed.Host != "auth.example.com" {
		t.Errorf("Host = %q, want %q", parsed.Host, "auth.example.com")
	}
	if parsed.Path != "/authorize" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/authorize")
	}
}

func TestBuildAuthorizationURL_DeprecatedDomainKeycloakWrong(t *testing.T) {
	// The deprecated Domain field always produces /authorize, but Keycloak uses
	// /protocol/openid-connect/auth. Verify this mismatch is visible.
	pm := NewPKCEManager()
	ctx := context.Background()

	// A Keycloak-style domain would have a realm path, but Domain only takes a hostname
	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Domain:      "auth.trial.barndoor.ai",
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
		Audience:    "https://barndoor.ai/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	parsed, _ := url.Parse(authURL)

	// Domain path produces /authorize — wrong for Keycloak, which needs
	// /realms/<realm>/protocol/openid-connect/auth
	if parsed.Path != "/authorize" {
		t.Errorf("Deprecated Domain path = %q, want /authorize (known limitation)", parsed.Path)
	}
}

func TestBuildAuthorizationURL_CustomScope(t *testing.T) {
	ClearOidcConfigCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // trigger fallback
	}))
	defer server.Close()

	pm := NewPKCEManager()
	ctx := context.Background()

	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
		Audience:    "https://api.example.com/",
		Scope:       "openid offline_access",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	parsed, _ := url.Parse(authURL)
	if parsed.Query().Get("scope") != "openid offline_access" {
		t.Errorf("scope = %q, want %q", parsed.Query().Get("scope"), "openid offline_access")
	}
}

func TestBuildAuthorizationURL_NoIssuerOrDomain(t *testing.T) {
	pm := NewPKCEManager()
	ctx := context.Background()

	_, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
	})
	if err == nil {
		t.Fatal("Expected error when neither Issuer nor Domain is provided")
	}
}

func TestBuildAuthorizationURL_IssuerTakesPrecedenceOverDomain(t *testing.T) {
	ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"authorization_endpoint": server.URL + "/from-issuer/authorize",
			"token_endpoint":         server.URL + "/from-issuer/token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	}))
	defer server.Close()

	pm := NewPKCEManager()
	ctx := context.Background()

	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		Domain:      "should-be-ignored.example.com",
		ClientID:    "test-client",
		RedirectURI: "http://localhost:8080/cb",
		Audience:    "https://api.example.com/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	parsed, _ := url.Parse(authURL)
	if parsed.Path != "/from-issuer/authorize" {
		t.Errorf("Expected Issuer path, got %q (Domain was not ignored)", parsed.Path)
	}
}

// ---------------------------------------------------------------------------
// PKCE mechanics
// ---------------------------------------------------------------------------

func TestPKCE_CodeVerifierLength(t *testing.T) {
	pm := NewPKCEManager()
	ctx := context.Background()

	ClearOidcConfigCache()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test",
		RedirectURI: "http://localhost/cb",
		Audience:    "https://api.example.com/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	verifier, state := pm.GetState()
	if verifier == "" {
		t.Fatal("Code verifier is empty")
	}
	if state == "" {
		t.Fatal("State is empty")
	}

	// RFC 7636: code_verifier must be 43-128 characters
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("Code verifier length = %d, must be 43-128 per RFC 7636", len(verifier))
	}
}

func TestPKCE_CodeChallengeIsS256(t *testing.T) {
	pm := NewPKCEManager()
	ctx := context.Background()

	ClearOidcConfigCache()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	authURL, err := pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test",
		RedirectURI: "http://localhost/cb",
		Audience:    "https://api.example.com/",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL failed: %v", err)
	}

	verifier, _ := pm.GetState()
	parsed, _ := url.Parse(authURL)
	challenge := parsed.Query().Get("code_challenge")

	// Manually compute expected challenge: BASE64URL(SHA256(ASCII(code_verifier)))
	h := sha256.Sum256([]byte(verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	if challenge != expectedChallenge {
		t.Errorf("code_challenge mismatch:\n  got:  %q\n  want: %q", challenge, expectedChallenge)
	}
}

func TestPKCE_UniquePerCall(t *testing.T) {
	ClearOidcConfigCache()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	params := AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test",
		RedirectURI: "http://localhost/cb",
		Audience:    "https://api.example.com/",
	}
	ctx := context.Background()

	pm := NewPKCEManager()
	_, _ = pm.BuildAuthorizationURL(ctx, params)
	v1, s1 := pm.GetState()

	pm2 := NewPKCEManager()
	_, _ = pm2.BuildAuthorizationURL(ctx, params)
	v2, s2 := pm2.GetState()

	if v1 == v2 {
		t.Error("Two PKCE managers generated the same code verifier")
	}
	if s1 == s2 {
		t.Error("Two PKCE managers generated the same state")
	}
}

func TestPKCE_ValidateState(t *testing.T) {
	pm := NewPKCEManager()
	ctx := context.Background()

	ClearOidcConfigCache()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, _ = pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test",
		RedirectURI: "http://localhost/cb",
		Audience:    "https://api.example.com/",
	})

	_, state := pm.GetState()

	if !pm.ValidateState(state) {
		t.Error("ValidateState rejected correct state")
	}
	if pm.ValidateState("wrong-state") {
		t.Error("ValidateState accepted wrong state")
	}
	if pm.ValidateState("") {
		t.Error("ValidateState accepted empty state")
	}
}

func TestPKCE_ClearState(t *testing.T) {
	pm := NewPKCEManager()
	ctx := context.Background()

	ClearOidcConfigCache()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, _ = pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test",
		RedirectURI: "http://localhost/cb",
		Audience:    "https://api.example.com/",
	})

	pm.ClearState()
	v, s := pm.GetState()

	if v != "" || s != "" {
		t.Errorf("After ClearState: verifier=%q, state=%q, want empty", v, s)
	}
}

// ---------------------------------------------------------------------------
// ExchangeCodeForToken
// ---------------------------------------------------------------------------

func TestExchangeCodeForToken_Success(t *testing.T) {
	ClearOidcConfigCache()

	var receivedBody url.Values
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			cfg := map[string]string{
				"token_endpoint":         server.URL + "/oauth/token",
				"authorization_endpoint": server.URL + "/authorize",
			}
			json.NewEncoder(w).Encode(cfg)
			return
		}
		if r.URL.Path == "/oauth/token" && r.Method == http.MethodPost {
			r.ParseForm()
			receivedBody = r.Form
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	pm := NewPKCEManager()
	ctx := context.Background()

	// Build auth URL first to set PKCE state
	_, _ = pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost/cb",
		Audience:    "https://api.example.com/",
	})

	verifier, _ := pm.GetState()

	tokenData, err := pm.ExchangeCodeForToken(ctx, TokenExchangeParams{
		Issuer:       server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Code:         "auth-code-123",
		RedirectURI:  "http://localhost/cb",
	})
	if err != nil {
		t.Fatalf("ExchangeCodeForToken failed: %v", err)
	}

	if tokenData["access_token"] != "test-token" {
		t.Errorf("access_token = %v, want %q", tokenData["access_token"], "test-token")
	}

	// Verify the code_verifier was sent
	if receivedBody.Get("code_verifier") != verifier {
		t.Errorf("code_verifier = %q, want %q", receivedBody.Get("code_verifier"), verifier)
	}
	if receivedBody.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q, want %q", receivedBody.Get("grant_type"), "authorization_code")
	}
}

func TestExchangeCodeForToken_ServerError(t *testing.T) {
	ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			cfg := map[string]string{
				"token_endpoint":         server.URL + "/oauth/token",
				"authorization_endpoint": server.URL + "/authorize",
			}
			json.NewEncoder(w).Encode(cfg)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Code expired"}`)
	}))
	defer server.Close()

	pm := NewPKCEManager()
	ctx := context.Background()

	_, err := pm.ExchangeCodeForToken(ctx, TokenExchangeParams{
		Issuer:       server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Code:         "expired-code",
		RedirectURI:  "http://localhost/cb",
	})
	if err == nil {
		t.Fatal("Expected error for failed token exchange")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("Error should mention invalid_grant, got: %v", err)
	}
}

func TestExchangeCodeForToken_NoIssuerOrDomain(t *testing.T) {
	pm := NewPKCEManager()
	ctx := context.Background()

	_, err := pm.ExchangeCodeForToken(ctx, TokenExchangeParams{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Code:         "code",
		RedirectURI:  "http://localhost/cb",
	})
	if err == nil {
		t.Fatal("Expected error when neither Issuer nor Domain is provided")
	}
}

func TestExchangeCodeForToken_NoSecretOrVerifier(t *testing.T) {
	ClearOidcConfigCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // trigger fallback for OIDC
	}))
	defer server.Close()

	// Fresh PKCEManager — no verifier set
	pm := NewPKCEManager()
	ctx := context.Background()

	_, err := pm.ExchangeCodeForToken(ctx, TokenExchangeParams{
		Issuer:      server.URL,
		ClientID:    "test-client",
		Code:        "code",
		RedirectURI: "http://localhost/cb",
		// No ClientSecret and no PKCE verifier
	})
	if err == nil {
		t.Fatal("Expected error when neither client_secret nor PKCE verifier is present")
	}
}

func TestExchangeCodeForToken_ClearsState(t *testing.T) {
	ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			cfg := map[string]string{
				"token_endpoint":         server.URL + "/oauth/token",
				"authorization_endpoint": server.URL + "/authorize",
			}
			json.NewEncoder(w).Encode(cfg)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok"}`)
	}))
	defer server.Close()

	pm := NewPKCEManager()
	ctx := context.Background()

	_, _ = pm.BuildAuthorizationURL(ctx, AuthorizationURLParams{
		Issuer: server.URL, ClientID: "c", RedirectURI: "http://localhost/cb", Audience: "a",
	})

	_, _ = pm.ExchangeCodeForToken(ctx, TokenExchangeParams{
		Issuer: server.URL, ClientID: "c", ClientSecret: "s", Code: "code", RedirectURI: "http://localhost/cb",
	})

	v, s := pm.GetState()
	if v != "" || s != "" {
		t.Errorf("State not cleared after exchange: verifier=%q, state=%q", v, s)
	}
}

// ---------------------------------------------------------------------------
// normalizeEnvironmentMode
// ---------------------------------------------------------------------------

func TestNormalizeEnvironmentMode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"production", "production"},
		{"prod", "production"},
		{"PRODUCTION", "production"},
		{"Prod", "production"},
		{"uat", "uat"},
		{"UAT", "uat"},
		{"dev", "dev"},
		{"development", "dev"},
		{"DEVELOPMENT", "dev"},
		{"enterprise-production", "enterprise-production"},
		{"enterprise-prod", "enterprise-production"},
		{"enterprise", "enterprise-production"},
		{"ENTERPRISE", "enterprise-production"},
		{"Enterprise-Production", "enterprise-production"},
		{"enterprise-uat", "enterprise-uat"},
		{"enterprise-dev", "enterprise-dev"},
		{"localdev", "localdev"},
		{"local", "localdev"},
		// Unknown values default to production
		{"unknown", "production"},
		{"staging", "production"},
		{"", "production"},
		// Underscore variants — not in the map, so they default to production
		{"enterprise_production", "production"},
		{"enterprise_prod", "production"},
		{"enterprise_uat", "production"},
		{"enterprise_dev", "production"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeEnvironmentMode(tt.input)
			if got != tt.want {
				t.Errorf("normalizeEnvironmentMode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AuthConfig consistency
// ---------------------------------------------------------------------------

func TestAuthConfig_AllEnvironmentsPresent(t *testing.T) {
	expected := []string{
		"production", "uat", "dev",
		"enterprise-production", "enterprise-uat", "enterprise-dev",
		"localdev",
	}
	for _, env := range expected {
		if _, ok := AuthConfig[env]; !ok {
			t.Errorf("AuthConfig missing expected environment %q", env)
		}
	}
}

func TestAuthConfig_AllEnvironmentsHaveRequiredFields(t *testing.T) {
	for env, cfg := range AuthConfig {
		if cfg.Issuer == "" {
			t.Errorf("AuthConfig[%q].Issuer is empty", env)
		}
		if cfg.Audience == "" {
			t.Errorf("AuthConfig[%q].Audience is empty", env)
		}
		if cfg.BaseURL == "" {
			t.Errorf("AuthConfig[%q].BaseURL is empty", env)
		}
	}
}

func TestAuthConfig_KeycloakEnvironmentsHaveRealms(t *testing.T) {
	keycloakEnvs := []string{"production", "uat", "dev", "localdev"}
	for _, env := range keycloakEnvs {
		cfg := AuthConfig[env]
		if !strings.Contains(cfg.Issuer, "/realms/") {
			t.Errorf("Keycloak env %q issuer %q should contain /realms/", env, cfg.Issuer)
		}
	}
}

func TestAuthConfig_EnterpriseEnvironmentsAreAuth0(t *testing.T) {
	auth0Envs := []string{"enterprise-production", "enterprise-uat", "enterprise-dev"}
	for _, env := range auth0Envs {
		cfg := AuthConfig[env]
		if strings.Contains(cfg.Issuer, "/realms/") {
			t.Errorf("Auth0 env %q issuer %q should NOT contain /realms/", env, cfg.Issuer)
		}
	}
}

func TestAuthConfig_BaseURLContainsOrgSlugPlaceholder(t *testing.T) {
	for env, cfg := range AuthConfig {
		if env == "localdev" {
			continue // localdev uses localhost without org slug
		}
		if !strings.Contains(cfg.BaseURL, "{org_slug}") {
			t.Errorf("AuthConfig[%q].BaseURL = %q, expected {org_slug} placeholder", env, cfg.BaseURL)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers: base64URLDecode, generateRandomString, sha256Hash
// ---------------------------------------------------------------------------

func TestBase64URLDecode_NoPadding(t *testing.T) {
	// Standard base64url-encoded "hello" without padding
	encoded := base64.RawURLEncoding.EncodeToString([]byte("hello"))
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("base64URLDecode failed: %v", err)
	}
	if string(decoded) != "hello" {
		t.Errorf("Decoded = %q, want %q", string(decoded), "hello")
	}
}

func TestBase64URLDecode_WithURLSafeChars(t *testing.T) {
	// bytes that produce + and / in standard base64 should use - and _ in URL-safe
	data := []byte{0xfb, 0xff, 0xfe}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("base64URLDecode failed: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("Round-trip failed")
	}
}

func TestGenerateRandomString_Length(t *testing.T) {
	s := generateRandomString(32)
	// 32 bytes → 43 base64url characters (no padding)
	if len(s) != 43 {
		t.Errorf("generateRandomString(32) produced %d chars, want 43", len(s))
	}
}

func TestGenerateRandomString_Unique(t *testing.T) {
	a := generateRandomString(32)
	b := generateRandomString(32)
	if a == b {
		t.Error("Two random strings should not be equal")
	}
}

// ---------------------------------------------------------------------------
// Logger: messages containing % must not be treated as format strings
// ---------------------------------------------------------------------------

func TestLogger_URLEncodedMessageNotMangled(t *testing.T) {
	// Simulate what happens when an auth URL with %-encoded characters is logged.
	// Before the fix, log.Printf("[INFO] " + message) treated the message as a
	// format string, mangling %3A → %!A(MISSING) and %2F → %!F(MISSING).

	var captured string
	origLogger := GetLogger()
	defer SetLogger(origLogger)

	SetLogger(&captureLogger{fn: func(msg string) { captured = msg }})

	logger := createScopedLogger("test")

	// This URL mirrors what BuildAuthorizationURL produces
	url := "https://auth.example.com/authorize?audience=https%3A%2F%2Fbarndoor.ai%2F&client_id=test"
	logger.Info(fmt.Sprintf("Auth URL: %s", url))

	if strings.Contains(captured, "MISSING") {
		t.Errorf("Logger mangled URL-encoded message: %s", captured)
	}
	if !strings.Contains(captured, "https%3A%2F%2Fbarndoor.ai%2F") {
		t.Errorf("Logger lost URL-encoded characters: %s", captured)
	}
}

// captureLogger captures the last message logged at any level.
type captureLogger struct {
	fn func(string)
}

func (l *captureLogger) Debug(message string, args ...any) { l.fn(message) }
func (l *captureLogger) Info(message string, args ...any)  { l.fn(message) }
func (l *captureLogger) Warn(message string, args ...any)  { l.fn(message) }
func (l *captureLogger) Error(message string, args ...any) { l.fn(message) }
