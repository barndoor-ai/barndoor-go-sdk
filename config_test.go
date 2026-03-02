package barndoor

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// makeTestJWT creates a fake JWT with the given claims payload.
// The token is not cryptographically signed — it's only useful for
// functions that decode the payload without verifying the signature.
func makeTestJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".fakesignature"
}

// ---------------------------------------------------------------------------
// getEnvVar
// ---------------------------------------------------------------------------

func TestGetEnvVar_Set(t *testing.T) {
	t.Setenv("TEST_BARNDOOR_VAR", "hello")
	got := getEnvVar("TEST_BARNDOOR_VAR", "default")
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestGetEnvVar_NotSet(t *testing.T) {
	got := getEnvVar("TEST_BARNDOOR_UNSET_VAR_12345", "default")
	if got != "default" {
		t.Errorf("got %q, want %q", got, "default")
	}
}

// ---------------------------------------------------------------------------
// NewBarndoorConfig
// ---------------------------------------------------------------------------

func TestNewBarndoorConfig_NilOpts(t *testing.T) {
	// Clear env vars that might interfere
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "")
	t.Setenv("AUTH_URL", "")
	t.Setenv("AUTH_DOMAIN", "")
	t.Setenv("AGENT_CLIENT_ID", "")
	t.Setenv("AGENT_CLIENT_SECRET", "")
	t.Setenv("AUTH_CLIENT_ID", "")
	t.Setenv("AUTH_CLIENT_SECRET", "")
	t.Setenv("API_AUDIENCE", "")
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "")

	cfg := NewBarndoorConfig(nil)
	if cfg.Environment != "production" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "production")
	}
	if cfg.AuthIssuer == "" {
		t.Error("AuthIssuer should not be empty")
	}
	if cfg.APIAudience == "" {
		t.Error("APIAudience should not be empty")
	}
}

func TestNewBarndoorConfig_WithEnvironment(t *testing.T) {
	cfg := NewBarndoorConfig(&BarndoorConfigOptions{
		Environment: "enterprise-production",
	})
	if cfg.Environment != "enterprise-production" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "enterprise-production")
	}
	if !strings.Contains(cfg.AuthIssuer, "auth.barndoor.ai") {
		t.Errorf("AuthIssuer = %q, expected enterprise issuer", cfg.AuthIssuer)
	}
}

func TestNewBarndoorConfig_EnvFromMODE(t *testing.T) {
	t.Setenv("MODE", "dev")
	t.Setenv("BARNDOOR_ENV", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.Environment != "dev" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "dev")
	}
}

func TestNewBarndoorConfig_EnvFromBARNDOOR_ENV(t *testing.T) {
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "uat")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.Environment != "uat" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "uat")
	}
}

func TestNewBarndoorConfig_AuthIssuerFromOpts(t *testing.T) {
	cfg := NewBarndoorConfig(&BarndoorConfigOptions{
		AuthIssuer: "https://custom-issuer.example.com",
	})
	if cfg.AuthIssuer != "https://custom-issuer.example.com" {
		t.Errorf("AuthIssuer = %q", cfg.AuthIssuer)
	}
}

func TestNewBarndoorConfig_AuthIssuerFromAUTH_URL(t *testing.T) {
	t.Setenv("AUTH_URL", "https://auth-url.example.com")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.AuthIssuer != "https://auth-url.example.com" {
		t.Errorf("AuthIssuer = %q, want AUTH_URL value", cfg.AuthIssuer)
	}
}

func TestNewBarndoorConfig_AuthDomainFromOpts(t *testing.T) {
	t.Setenv("AUTH_URL", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{
		AuthDomain: "auth.example.com",
	})
	if cfg.AuthIssuer != "https://auth.example.com" {
		t.Errorf("AuthIssuer = %q, want https://auth.example.com", cfg.AuthIssuer)
	}
}

func TestNewBarndoorConfig_AuthDomainWithHTTP(t *testing.T) {
	t.Setenv("AUTH_URL", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{
		AuthDomain: "http://localhost:8080",
	})
	if cfg.AuthIssuer != "http://localhost:8080" {
		t.Errorf("AuthIssuer = %q, want http://localhost:8080", cfg.AuthIssuer)
	}
}

func TestNewBarndoorConfig_AuthDomainFromEnv(t *testing.T) {
	t.Setenv("AUTH_URL", "")
	t.Setenv("AUTH_DOMAIN", "env-auth.example.com")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.AuthIssuer != "https://env-auth.example.com" {
		t.Errorf("AuthIssuer = %q", cfg.AuthIssuer)
	}
}

func TestNewBarndoorConfig_AuthDomainFromEnvWithHTTP(t *testing.T) {
	t.Setenv("AUTH_URL", "")
	t.Setenv("AUTH_DOMAIN", "http://localhost:9090")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.AuthIssuer != "http://localhost:9090" {
		t.Errorf("AuthIssuer = %q", cfg.AuthIssuer)
	}
}

func TestNewBarndoorConfig_ClientIDFromOpts(t *testing.T) {
	t.Setenv("AGENT_CLIENT_ID", "")
	t.Setenv("AUTH_CLIENT_ID", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{ClientID: "my-client"})
	if cfg.ClientID != "my-client" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
}

func TestNewBarndoorConfig_ClientIDFromAgentEnv(t *testing.T) {
	t.Setenv("AGENT_CLIENT_ID", "agent-client")
	t.Setenv("AUTH_CLIENT_ID", "auth-client")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.ClientID != "agent-client" {
		t.Errorf("ClientID = %q, want AGENT_CLIENT_ID", cfg.ClientID)
	}
}

func TestNewBarndoorConfig_ClientIDFromAuthEnv(t *testing.T) {
	t.Setenv("AGENT_CLIENT_ID", "")
	t.Setenv("AUTH_CLIENT_ID", "auth-client")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.ClientID != "auth-client" {
		t.Errorf("ClientID = %q, want AUTH_CLIENT_ID", cfg.ClientID)
	}
}

func TestNewBarndoorConfig_ClientSecretFromOpts(t *testing.T) {
	t.Setenv("AGENT_CLIENT_SECRET", "")
	t.Setenv("AUTH_CLIENT_SECRET", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{ClientSecret: "my-secret"})
	if cfg.ClientSecret != "my-secret" {
		t.Errorf("ClientSecret = %q", cfg.ClientSecret)
	}
}

func TestNewBarndoorConfig_ClientSecretFromEnv(t *testing.T) {
	t.Setenv("AGENT_CLIENT_SECRET", "agent-secret")
	t.Setenv("AUTH_CLIENT_SECRET", "auth-secret")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.ClientSecret != "agent-secret" {
		t.Errorf("ClientSecret = %q, want AGENT_CLIENT_SECRET", cfg.ClientSecret)
	}
}

func TestNewBarndoorConfig_ClientSecretFromAuthEnv(t *testing.T) {
	t.Setenv("AGENT_CLIENT_SECRET", "")
	t.Setenv("AUTH_CLIENT_SECRET", "auth-secret")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.ClientSecret != "auth-secret" {
		t.Errorf("ClientSecret = %q, want AUTH_CLIENT_SECRET", cfg.ClientSecret)
	}
}

func TestNewBarndoorConfig_APIAudienceFromOpts(t *testing.T) {
	t.Setenv("API_AUDIENCE", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{APIAudience: "https://custom/"})
	if cfg.APIAudience != "https://custom/" {
		t.Errorf("APIAudience = %q", cfg.APIAudience)
	}
}

func TestNewBarndoorConfig_APIAudienceFromEnv(t *testing.T) {
	t.Setenv("API_AUDIENCE", "https://env-audience/")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.APIAudience != "https://env-audience/" {
		t.Errorf("APIAudience = %q", cfg.APIAudience)
	}
}

func TestNewBarndoorConfig_BaseURLFromOpts(t *testing.T) {
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{BaseURL: "https://custom.example.com"})
	if cfg.BaseURL != "https://custom.example.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
}

func TestNewBarndoorConfig_BaseURLFromBarndoorAPI(t *testing.T) {
	t.Setenv("BARNDOOR_API", "https://api-env.example.com")
	t.Setenv("BARNDOOR_URL", "")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.BaseURL != "https://api-env.example.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
}

func TestNewBarndoorConfig_BaseURLFromBarndoorURL(t *testing.T) {
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "https://url-env.example.com")

	cfg := NewBarndoorConfig(&BarndoorConfigOptions{})
	if cfg.BaseURL != "https://url-env.example.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
}

func TestNewBarndoorConfig_PromptForLogin(t *testing.T) {
	cfg := NewBarndoorConfig(&BarndoorConfigOptions{PromptForLogin: true})
	if !cfg.PromptForLogin {
		t.Error("PromptForLogin should be true")
	}
}

func TestNewBarndoorConfig_SkipLoginLocal(t *testing.T) {
	cfg := NewBarndoorConfig(&BarndoorConfigOptions{SkipLoginLocal: true})
	if !cfg.SkipLoginLocal {
		t.Error("SkipLoginLocal should be true")
	}
}

// ---------------------------------------------------------------------------
// GetStaticConfig
// ---------------------------------------------------------------------------

func TestGetStaticConfig(t *testing.T) {
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "")

	cfg := GetStaticConfig()
	if cfg == nil {
		t.Fatal("GetStaticConfig returned nil")
	}
	if cfg.Environment != "production" {
		t.Errorf("Environment = %q, want production", cfg.Environment)
	}
}

// ---------------------------------------------------------------------------
// BarndoorConfig.Validate
// ---------------------------------------------------------------------------

func TestBarndoorConfig_Validate_Valid(t *testing.T) {
	cfg := &BarndoorConfig{
		AuthIssuer:  "https://auth.example.com",
		APIAudience: "https://api.example.com/",
		BaseURL:     "https://example.com",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBarndoorConfig_Validate_MissingIssuer(t *testing.T) {
	cfg := &BarndoorConfig{
		APIAudience: "https://api.example.com/",
		BaseURL:     "https://example.com",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing AuthIssuer")
	}
}

func TestBarndoorConfig_Validate_MissingAudience(t *testing.T) {
	cfg := &BarndoorConfig{
		AuthIssuer: "https://auth.example.com",
		BaseURL:    "https://example.com",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing APIAudience")
	}
}

func TestBarndoorConfig_Validate_MissingBaseURL(t *testing.T) {
	cfg := &BarndoorConfig{
		AuthIssuer:  "https://auth.example.com",
		APIAudience: "https://api.example.com/",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing BaseURL")
	}
}

func TestBarndoorConfig_Validate_WhitespaceOnly(t *testing.T) {
	cfg := &BarndoorConfig{
		AuthIssuer:  "   ",
		APIAudience: "https://api.example.com/",
		BaseURL:     "https://example.com",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for whitespace-only AuthIssuer")
	}
}

// ---------------------------------------------------------------------------
// extractOrganizationIDSafe
// ---------------------------------------------------------------------------

func TestExtractOrganizationIDSafe_FromUserObject(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"sub": "user1",
		"user": map[string]any{
			"organization_name": "acme-corp",
		},
	})
	result := extractOrganizationIDSafe(token)
	if !result.HasOrganization {
		t.Fatal("expected HasOrganization=true")
	}
	if result.OrganizationID != "acme-corp" {
		t.Errorf("OrganizationID = %q, want %q", result.OrganizationID, "acme-corp")
	}
}

func TestExtractOrganizationIDSafe_FromUserSlug(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"user": map[string]any{
			"organization_slug": "myorg",
		},
	})
	result := extractOrganizationIDSafe(token)
	if !result.HasOrganization {
		t.Fatal("expected HasOrganization=true")
	}
	if result.OrganizationID != "myorg" {
		t.Errorf("OrganizationID = %q, want %q", result.OrganizationID, "myorg")
	}
}

func TestExtractOrganizationIDSafe_FromTopLevelClaim(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"organization_name": "top-level-org",
	})
	result := extractOrganizationIDSafe(token)
	if !result.HasOrganization {
		t.Fatal("expected HasOrganization=true")
	}
	if result.OrganizationID != "top-level-org" {
		t.Errorf("OrganizationID = %q", result.OrganizationID)
	}
}

func TestExtractOrganizationIDSafe_FromCustomClaim(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"https://barndoor.ai/organization_slug": "custom-org",
	})
	result := extractOrganizationIDSafe(token)
	if !result.HasOrganization {
		t.Fatal("expected HasOrganization=true")
	}
	if result.OrganizationID != "custom-org" {
		t.Errorf("OrganizationID = %q", result.OrganizationID)
	}
}

func TestExtractOrganizationIDSafe_FromOrgSlug(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"org_slug": "slug-org",
	})
	result := extractOrganizationIDSafe(token)
	if !result.HasOrganization {
		t.Fatal("expected HasOrganization=true")
	}
	if result.OrganizationID != "slug-org" {
		t.Errorf("OrganizationID = %q", result.OrganizationID)
	}
}

func TestExtractOrganizationIDSafe_NoOrg(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"sub": "user1",
	})
	result := extractOrganizationIDSafe(token)
	if result.HasOrganization {
		t.Error("expected HasOrganization=false")
	}
	if result.Error == "" {
		t.Error("expected an error message")
	}
}

func TestExtractOrganizationIDSafe_InvalidJWT(t *testing.T) {
	result := extractOrganizationIDSafe("not-a-jwt")
	if result.HasOrganization {
		t.Error("expected HasOrganization=false")
	}
	if !strings.Contains(result.Error, "Invalid JWT format") {
		t.Errorf("unexpected error: %q", result.Error)
	}
}

func TestExtractOrganizationIDSafe_InvalidBase64(t *testing.T) {
	result := extractOrganizationIDSafe("header.!!!invalid!!!.sig")
	if result.HasOrganization {
		t.Error("expected HasOrganization=false")
	}
	if !strings.Contains(result.Error, "corrupted") {
		t.Errorf("unexpected error: %q", result.Error)
	}
}

func TestExtractOrganizationIDSafe_InvalidJSON(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	token := "header." + payload + ".sig"
	result := extractOrganizationIDSafe(token)
	if result.HasOrganization {
		t.Error("expected HasOrganization=false")
	}
}

func TestExtractOrganizationIDSafe_WhitespaceOrg(t *testing.T) {
	token := makeTestJWT(map[string]any{
		"organization_name": "   ",
	})
	result := extractOrganizationIDSafe(token)
	if result.HasOrganization {
		t.Error("expected HasOrganization=false for whitespace-only org")
	}
}

// ---------------------------------------------------------------------------
// CheckTokenOrganization / HasOrganizationInfo
// ---------------------------------------------------------------------------

func TestCheckTokenOrganization(t *testing.T) {
	token := makeTestJWT(map[string]any{"org_slug": "test-org"})
	result := CheckTokenOrganization(token)
	if !result.HasOrganization {
		t.Error("expected HasOrganization=true")
	}
}

func TestHasOrganizationInfo_True(t *testing.T) {
	token := makeTestJWT(map[string]any{"org_slug": "test-org"})
	if !HasOrganizationInfo(token) {
		t.Error("expected true")
	}
}

func TestHasOrganizationInfo_False(t *testing.T) {
	token := makeTestJWT(map[string]any{"sub": "user1"})
	if HasOrganizationInfo(token) {
		t.Error("expected false")
	}
}

// ---------------------------------------------------------------------------
// GetDynamicConfig
// ---------------------------------------------------------------------------

func TestGetDynamicConfig_WithOrganization(t *testing.T) {
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "production")
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "")

	token := makeTestJWT(map[string]any{"org_slug": "acme"})
	cfg, err := GetDynamicConfig(token, true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(cfg.BaseURL, "{org_slug}") {
		t.Errorf("BaseURL still has placeholder: %q", cfg.BaseURL)
	}
	if !strings.Contains(cfg.BaseURL, "acme") {
		t.Errorf("BaseURL should contain org slug: %q", cfg.BaseURL)
	}
}

func TestGetDynamicConfig_InvalidSubdomain(t *testing.T) {
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "production")
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "")

	token := makeTestJWT(map[string]any{"org_slug": "INVALID SLUG!"})
	_, err := GetDynamicConfig(token, true, "")
	if err == nil {
		t.Fatal("expected error for invalid subdomain format")
	}
}

func TestGetDynamicConfig_FallbackOrg(t *testing.T) {
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "production")
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "")

	token := makeTestJWT(map[string]any{"sub": "user1"}) // no org
	cfg, err := GetDynamicConfig(token, false, "fallback-org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg.BaseURL, "fallback-org") {
		t.Errorf("BaseURL should contain fallback org: %q", cfg.BaseURL)
	}
}

func TestGetDynamicConfig_RequireOrgMissing(t *testing.T) {
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "production")
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "")

	token := makeTestJWT(map[string]any{"sub": "user1"})
	_, err := GetDynamicConfig(token, true, "")
	if err == nil {
		t.Fatal("expected error when requireOrganization=true and no org in token")
	}
}

func TestGetDynamicConfig_NoOrgNotRequired(t *testing.T) {
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "production")
	t.Setenv("BARNDOOR_API", "")
	t.Setenv("BARNDOOR_URL", "")

	token := makeTestJWT(map[string]any{"sub": "user1"})
	cfg, err := GetDynamicConfig(token, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("config should not be nil")
	}
}

// ---------------------------------------------------------------------------
// base64URLDecode
// ---------------------------------------------------------------------------

func TestBase64URLDecode_Padding2(t *testing.T) {
	// len(s) % 4 == 2 → needs "=="
	encoded := base64.RawURLEncoding.EncodeToString([]byte("ab"))
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != "ab" {
		t.Errorf("got %q, want %q", string(decoded), "ab")
	}
}

func TestBase64URLDecode_Padding3(t *testing.T) {
	// len(s) % 4 == 3 → needs "="
	encoded := base64.RawURLEncoding.EncodeToString([]byte("abc"))
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != "abc" {
		t.Errorf("got %q, want %q", string(decoded), "abc")
	}
}

func TestBase64URLDecode_NoPaddingNeeded(t *testing.T) {
	// len(s) % 4 == 0 → no padding needed
	encoded := base64.RawURLEncoding.EncodeToString([]byte("abcd"))
	// Ensure length is multiple of 4 with no extra padding
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != "abcd" {
		t.Errorf("got %q, want %q", string(decoded), "abcd")
	}
}
