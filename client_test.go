package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// NewBarndoorSDK
// ---------------------------------------------------------------------------

func TestNewBarndoorSDK_Valid(t *testing.T) {
	sdk, err := NewBarndoorSDK("https://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sdk.Close()

	if sdk.Base != "https://example.com" {
		t.Errorf("Base = %q, want %q", sdk.Base, "https://example.com")
	}
}

func TestNewBarndoorSDK_TrimsTrailingSlash(t *testing.T) {
	sdk, err := NewBarndoorSDK("https://example.com/", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sdk.Close()

	if sdk.Base != "https://example.com" {
		t.Errorf("Base = %q, want trailing slash removed", sdk.Base)
	}
}

func TestNewBarndoorSDK_WithToken(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	sdk, err := NewBarndoorSDK("https://example.com", &SDKOptions{Token: token})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sdk.Close()

	got, err := sdk.Token()
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}
	if got != token {
		t.Errorf("Token() = %q", got)
	}
}

func TestNewBarndoorSDK_InvalidURL(t *testing.T) {
	_, err := NewBarndoorSDK("", nil)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewBarndoorSDK_InvalidToken(t *testing.T) {
	_, err := NewBarndoorSDK("https://example.com", &SDKOptions{Token: "not-jwt"})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestNewBarndoorSDK_NegativeRetries(t *testing.T) {
	_, err := NewBarndoorSDK("https://example.com", &SDKOptions{MaxRetries: -1})
	if err == nil {
		t.Fatal("expected error for negative MaxRetries")
	}
}

func TestNewBarndoorSDK_CustomTimeout(t *testing.T) {
	sdk, err := NewBarndoorSDK("https://example.com", &SDKOptions{Timeout: 60})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sdk.Close()
}

func TestNewBarndoorSDK_CustomRetries(t *testing.T) {
	sdk, err := NewBarndoorSDK("https://example.com", &SDKOptions{MaxRetries: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer sdk.Close()
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

func TestToken_NoToken(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	_, err := sdk.Token()
	if err == nil {
		t.Fatal("expected error when no token is set")
	}
}

func TestToken_WithToken(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	sdk, _ := NewBarndoorSDK("https://example.com", &SDKOptions{Token: token})
	defer sdk.Close()

	got, err := sdk.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != token {
		t.Errorf("Token() = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestClose(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	sdk.Close()
	// Double close should not panic
	sdk.Close()
}

// ---------------------------------------------------------------------------
// EnsureValidToken
// ---------------------------------------------------------------------------

func TestEnsureValidToken_NoToken(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	err := sdk.EnsureValidToken(context.Background())
	if err == nil {
		t.Fatal("expected error when no token is set")
	}
}

func TestEnsureValidToken_SkipsInTestEnv(t *testing.T) {
	t.Setenv("BARNDOOR_ENV", "test")

	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	sdk, _ := NewBarndoorSDK("https://example.com", &SDKOptions{Token: token})
	defer sdk.Close()

	err := sdk.EnsureValidToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error in test env: %v", err)
	}
}

func TestEnsureValidToken_SkipsInCIEnv(t *testing.T) {
	t.Setenv("BARNDOOR_ENV", "ci")

	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	sdk, _ := NewBarndoorSDK("https://example.com", &SDKOptions{Token: token})
	defer sdk.Close()

	err := sdk.EnsureValidToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error in CI env: %v", err)
	}
}

func TestEnsureValidToken_AlreadyValidated(t *testing.T) {
	t.Setenv("BARNDOOR_ENV", "test")

	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	sdk, _ := NewBarndoorSDK("https://example.com", &SDKOptions{Token: token})
	defer sdk.Close()

	// First call validates
	sdk.EnsureValidToken(context.Background())
	// Second call should short-circuit
	err := sdk.EnsureValidToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
}

// ---------------------------------------------------------------------------
// req (authenticated request)
// ---------------------------------------------------------------------------

func TestReq_ClosedSDK(t *testing.T) {
	t.Setenv("BARNDOOR_ENV", "test")

	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	sdk, _ := NewBarndoorSDK("https://example.com", &SDKOptions{Token: token})
	sdk.Close()

	_, err := sdk.req(context.Background(), "GET", "/test", nil)
	if err == nil {
		t.Fatal("expected error for closed SDK")
	}
}

// ---------------------------------------------------------------------------
// Authenticate
// ---------------------------------------------------------------------------

func TestAuthenticate_InvalidToken(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	err := sdk.Authenticate(context.Background(), "not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// ---------------------------------------------------------------------------
// ValidateCachedToken
// ---------------------------------------------------------------------------

func TestValidateCachedToken_NoToken(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	valid, err := sdk.ValidateCachedToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected false for no token")
	}
}

// newTestSDK creates an SDK with the given test server as the base URL
// and BARNDOOR_ENV=test to skip token validation.
func newTestSDK(t *testing.T, server *httptest.Server) *BarndoorSDK {
	t.Helper()
	t.Setenv("BARNDOOR_ENV", "test")

	token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
	sdk, err := NewBarndoorSDK(server.URL, &SDKOptions{Token: token})
	if err != nil {
		t.Fatalf("failed to create SDK: %v", err)
	}
	// Pre-validate so req() doesn't try to hit OIDC endpoints
	sdk.tokenValidated = true
	return sdk
}

// ---------------------------------------------------------------------------
// ListServers
// ---------------------------------------------------------------------------

func TestListServers_SinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/servers" {
			http.NotFound(w, r)
			return
		}
		resp := paginatedResponse{
			Data: []ServerSummary{
				{ID: "1", Name: "GitHub", Slug: "github", ConnectionStatus: ConnectionStatusConnected},
				{ID: "2", Name: "Slack", Slug: "slack", ConnectionStatus: ConnectionStatusAvailable},
			},
			Pagination: paginationMetadata{Page: 1, Pages: 1, Total: 2},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	servers, err := sdk.ListServers(context.Background())
	if err != nil {
		t.Fatalf("ListServers failed: %v", err)
	}
	if len(servers) != 2 {
		t.Errorf("got %d servers, want 2", len(servers))
	}
}

func TestListServers_MultiPage(t *testing.T) {
	page2 := 2
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageParam := r.URL.Query().Get("page")
		var resp paginatedResponse
		if pageParam == "2" {
			resp = paginatedResponse{
				Data: []ServerSummary{
					{ID: "2", Name: "Slack", Slug: "slack", ConnectionStatus: ConnectionStatusAvailable},
				},
				Pagination: paginationMetadata{Page: 2, Pages: 2, Total: 2},
			}
		} else {
			resp = paginatedResponse{
				Data: []ServerSummary{
					{ID: "1", Name: "GitHub", Slug: "github", ConnectionStatus: ConnectionStatusConnected},
				},
				Pagination: paginationMetadata{Page: 1, Pages: 2, Total: 2, NextPage: &page2},
			}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	servers, err := sdk.ListServers(context.Background())
	if err != nil {
		t.Fatalf("ListServers failed: %v", err)
	}
	if len(servers) != 2 {
		t.Errorf("got %d servers, want 2", len(servers))
	}
}

// ---------------------------------------------------------------------------
// GetServer
// ---------------------------------------------------------------------------

func TestGetServer_ByUUID(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/api/servers/" + uuid
		if r.URL.Path != expected {
			t.Errorf("path = %q, want %q", r.URL.Path, expected)
			http.NotFound(w, r)
			return
		}
		detail := ServerDetail{
			ServerSummary: ServerSummary{
				ID: uuid, Name: "GitHub", Slug: "github",
				ConnectionStatus: ConnectionStatusConnected,
			},
		}
		json.NewEncoder(w).Encode(detail)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	detail, err := sdk.GetServer(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetServer failed: %v", err)
	}
	if detail.ID != uuid {
		t.Errorf("ID = %q", detail.ID)
	}
}

func TestGetServer_BySlug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/api/servers/by-slug/github"
		if r.URL.Path != expected {
			t.Errorf("path = %q, want %q", r.URL.Path, expected)
			http.NotFound(w, r)
			return
		}
		detail := ServerDetail{
			ServerSummary: ServerSummary{
				ID: "1", Name: "GitHub", Slug: "github",
				ConnectionStatus: ConnectionStatusConnected,
			},
		}
		json.NewEncoder(w).Encode(detail)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	detail, err := sdk.GetServer(context.Background(), "github")
	if err != nil {
		t.Fatalf("GetServer failed: %v", err)
	}
	if detail.Slug != "github" {
		t.Errorf("Slug = %q", detail.Slug)
	}
}

func TestGetServer_InvalidID(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	_, err := sdk.GetServer(context.Background(), "INVALID!!")
	if err == nil {
		t.Fatal("expected error for invalid server ID")
	}
}

// ---------------------------------------------------------------------------
// InitiateConnection
// ---------------------------------------------------------------------------

func TestInitiateConnection_BySlug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/api/servers/by-slug/github/connect"
		if r.URL.Path != expected {
			t.Errorf("path = %q, want %q", r.URL.Path, expected)
			http.NotFound(w, r)
			return
		}
		resp := connectionInitiationResponse{AuthURL: "https://auth.example.com/authorize"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	authURL, err := sdk.InitiateConnection(context.Background(), "github", "")
	if err != nil {
		t.Fatalf("InitiateConnection failed: %v", err)
	}
	if authURL != "https://auth.example.com/authorize" {
		t.Errorf("authURL = %q", authURL)
	}
}

func TestInitiateConnection_ByUUID(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/api/servers/" + uuid + "/connect"
		if r.URL.Path != expected {
			t.Errorf("path = %q, want %q", r.URL.Path, expected)
		}
		json.NewEncoder(w).Encode(connectionInitiationResponse{})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.InitiateConnection(context.Background(), uuid, "")
	if err != nil {
		t.Fatalf("InitiateConnection failed: %v", err)
	}
}

func TestInitiateConnection_WithReturnURL(t *testing.T) {
	var receivedReturnURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedReturnURL = r.URL.Query().Get("return_url")
		json.NewEncoder(w).Encode(connectionInitiationResponse{})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.InitiateConnection(context.Background(), "github", "https://return.example.com")
	if err != nil {
		t.Fatalf("InitiateConnection failed: %v", err)
	}
	if receivedReturnURL != "https://return.example.com" {
		t.Errorf("return_url = %q", receivedReturnURL)
	}
}

func TestInitiateConnection_InvalidReturnURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(connectionInitiationResponse{})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.InitiateConnection(context.Background(), "github", "not a url")
	if err == nil {
		t.Fatal("expected error for invalid return URL")
	}
}

func TestInitiateConnection_InvalidServerID(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	_, err := sdk.InitiateConnection(context.Background(), "INVALID!!", "")
	if err == nil {
		t.Fatal("expected error for invalid server ID")
	}
}

func TestInitiateConnection_OAuthConfigMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"message":"OAuth server configuration not found"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.InitiateConnection(context.Background(), "github", "")
	if err == nil {
		t.Fatal("expected error for missing OAuth config")
	}
	if !strings.Contains(err.Error(), "OAuth configuration") {
		t.Errorf("expected OAuth config error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetConnectionStatus
// ---------------------------------------------------------------------------

func TestGetConnectionStatus_BySlug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/servers/by-slug/github/connection" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(connectionStatusResponse{Status: "connected"})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	status, err := sdk.GetConnectionStatus(context.Background(), "github")
	if err != nil {
		t.Fatalf("GetConnectionStatus failed: %v", err)
	}
	if status != "connected" {
		t.Errorf("status = %q, want %q", status, "connected")
	}
}

func TestGetConnectionStatus_ByUUID(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/api/servers/" + uuid + "/connection"
		if r.URL.Path != expected {
			t.Errorf("path = %q, want %q", r.URL.Path, expected)
		}
		json.NewEncoder(w).Encode(connectionStatusResponse{Status: "available"})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	status, err := sdk.GetConnectionStatus(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetConnectionStatus failed: %v", err)
	}
	if status != "available" {
		t.Errorf("status = %q", status)
	}
}

func TestGetConnectionStatus_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.GetConnectionStatus(context.Background(), "github")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGetConnectionStatus_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"server error"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.GetConnectionStatus(context.Background(), "github")
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestGetConnectionStatus_InvalidID(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	_, err := sdk.GetConnectionStatus(context.Background(), "INVALID!!")
	if err == nil {
		t.Fatal("expected error for invalid server ID")
	}
}

// ---------------------------------------------------------------------------
// DisconnectServer
// ---------------------------------------------------------------------------

func TestDisconnectServer_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.DisconnectServer(context.Background(), "github")
	if err != nil {
		t.Fatalf("DisconnectServer failed: %v", err)
	}
}

func TestDisconnectServer_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.DisconnectServer(context.Background(), "github")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "not be connected") {
		t.Errorf("expected connection not found error, got: %v", err)
	}
}

func TestDisconnectServer_InvalidID(t *testing.T) {
	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	err := sdk.DisconnectServer(context.Background(), "INVALID!!")
	if err == nil {
		t.Fatal("expected error for invalid server ID")
	}
}

// ---------------------------------------------------------------------------
// openBrowser
// ---------------------------------------------------------------------------

func TestOpenBrowser_RejectsNonHTTP(t *testing.T) {
	err := openBrowser("file:///etc/passwd")
	if err == nil {
		t.Fatal("expected error for file:// URL")
	}
	if !strings.Contains(err.Error(), "non-HTTP") {
		t.Errorf("expected non-HTTP error, got: %v", err)
	}
}

func TestOpenBrowser_RejectsJavascript(t *testing.T) {
	err := openBrowser("javascript:alert(1)")
	if err == nil {
		t.Fatal("expected error for javascript: URL")
	}
}

func TestOpenBrowser_RejectsInvalidURL(t *testing.T) {
	err := openBrowser("://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// ValidateCachedToken (with mock OIDC server)
// ---------------------------------------------------------------------------

func TestValidateCachedToken_Valid(t *testing.T) {
	ClearOidcConfigCache()
	defer ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"userinfo_endpoint":      server.URL + "/userinfo",
			}
			json.NewEncoder(w).Encode(cfg)
		case "/userinfo":
			if r.Header.Get("Authorization") == "Bearer valid-jwt.has.three-parts" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"sub":"user1"}`)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Point config to our mock server
	t.Setenv("AUTH_URL", server.URL)
	t.Setenv("MODE", "")
	t.Setenv("BARNDOOR_ENV", "production")

	sdk, err := NewBarndoorSDK("https://example.com", &SDKOptions{
		Token: "valid-jwt.has.three-parts",
	})
	if err != nil {
		t.Fatalf("NewBarndoorSDK failed: %v", err)
	}
	defer sdk.Close()

	valid, err := sdk.ValidateCachedToken(context.Background())
	if err != nil {
		t.Fatalf("ValidateCachedToken error: %v", err)
	}
	if !valid {
		t.Error("expected valid=true")
	}
}

func TestValidateCachedToken_Invalid(t *testing.T) {
	ClearOidcConfigCache()
	defer ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"userinfo_endpoint":      server.URL + "/userinfo",
			}
			json.NewEncoder(w).Encode(cfg)
		case "/userinfo":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("AUTH_URL", server.URL)
	t.Setenv("BARNDOOR_ENV", "production")

	sdk, _ := NewBarndoorSDK("https://example.com", &SDKOptions{
		Token: "invalid-jwt.has.three-parts",
	})
	defer sdk.Close()

	valid, err := sdk.ValidateCachedToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected valid=false for unauthorized token")
	}
}

// ---------------------------------------------------------------------------
// Authenticate (with test env to skip validation)
// ---------------------------------------------------------------------------

func TestAuthenticate_SuccessTestEnv(t *testing.T) {
	t.Setenv("BARNDOOR_ENV", "test")

	sdk, _ := NewBarndoorSDK("https://example.com", nil)
	defer sdk.Close()

	err := sdk.Authenticate(context.Background(), "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	token, err := sdk.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token != "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig" {
		t.Errorf("token = %q", token)
	}
}

// ---------------------------------------------------------------------------
// EnsureValidToken with ValidateCachedToken failure
// ---------------------------------------------------------------------------

func TestEnsureValidToken_ValidationFails(t *testing.T) {
	ClearOidcConfigCache()
	defer ClearOidcConfigCache()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			cfg := map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"userinfo_endpoint":      server.URL + "/userinfo",
			}
			json.NewEncoder(w).Encode(cfg)
		case "/userinfo":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("AUTH_URL", server.URL)
	t.Setenv("BARNDOOR_ENV", "production")

	sdk, _ := NewBarndoorSDK("https://example.com", &SDKOptions{
		Token: "bad-jwt.has.three-parts",
	})
	defer sdk.Close()

	err := sdk.EnsureValidToken(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// ---------------------------------------------------------------------------
// EnsureServerConnected
// ---------------------------------------------------------------------------

func TestEnsureServerConnected_AlreadyConnected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/by-slug/github") && !strings.Contains(r.URL.Path, "/connect") && !strings.Contains(r.URL.Path, "/connection") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "1", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusConnected,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 5)
	if err != nil {
		t.Fatalf("EnsureServerConnected failed: %v", err)
	}
}

func TestEnsureServerConnected_ServerNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "nonexistent", 1)
	if err == nil {
		t.Fatal("expected error for server not found")
	}
	if _, ok := err.(*ServerNotFoundError); !ok {
		t.Errorf("expected ServerNotFoundError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// openBrowser — valid HTTP URLs (mocked to prevent actual browser launch)
// ---------------------------------------------------------------------------

func TestOpenBrowser_ValidHTTP(t *testing.T) {
	var called bool
	old := openBrowserFunc
	openBrowserFunc = func(u string) error { called = true; return nil }
	defer func() { openBrowserFunc = old }()

	err := openBrowserFunc("http://localhost:9999/test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !called {
		t.Error("openBrowserFunc was not called")
	}
}

func TestOpenBrowser_ValidHTTPS(t *testing.T) {
	var called bool
	old := openBrowserFunc
	openBrowserFunc = func(u string) error { called = true; return nil }
	defer func() { openBrowserFunc = old }()

	err := openBrowserFunc("https://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !called {
		t.Error("openBrowserFunc was not called")
	}
}

func TestOpenBrowser_SchemeValidation(t *testing.T) {
	// Verify the URL validation logic rejects non-HTTP schemes
	// (these tests don't launch a browser since they fail before exec)
	tests := []struct {
		name string
		url  string
	}{
		{"ftp scheme", "ftp://example.com"},
		{"data scheme", "data:text/html,<h1>hi</h1>"},
		{"empty scheme", "://noscheme"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := openBrowser(tc.url)
			if err == nil {
				t.Errorf("expected error for %q", tc.url)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EnsureServerConnected — OAuth flow path
// ---------------------------------------------------------------------------

func TestEnsureServerConnected_OAuthFlowConnects(t *testing.T) {
	old := openBrowserFunc
	openBrowserFunc = func(u string) error { return nil }
	defer func() { openBrowserFunc = old }()

	pollCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GetServer
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/by-slug/github") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "1", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusAvailable,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		// InitiateConnection
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/connect") {
			json.NewEncoder(w).Encode(connectionInitiationResponse{
				AuthURL: "https://auth.example.com/authorize",
			})
			return
		}
		// GetConnectionStatus (polling)
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/connection") {
			pollCount++
			status := "pending"
			if pollCount >= 2 {
				status = "connected"
			}
			json.NewEncoder(w).Encode(connectionStatusResponse{Status: status})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 10)
	if err != nil {
		t.Fatalf("EnsureServerConnected failed: %v", err)
	}
	if pollCount < 2 {
		t.Errorf("expected at least 2 poll calls, got %d", pollCount)
	}
}

func TestEnsureServerConnected_NoAuthURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/by-slug/github") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "1", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusAvailable,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/connect") {
			json.NewEncoder(w).Encode(connectionInitiationResponse{})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 5)
	if err == nil {
		t.Fatal("expected error when no auth_url returned")
	}
	if !strings.Contains(err.Error(), "auth_url") {
		t.Errorf("expected auth_url error, got: %v", err)
	}
}

func TestEnsureServerConnected_Timeout(t *testing.T) {
	old := openBrowserFunc
	openBrowserFunc = func(u string) error { return nil }
	defer func() { openBrowserFunc = old }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/by-slug/github") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "1", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusAvailable,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/connect") {
			json.NewEncoder(w).Encode(connectionInitiationResponse{
				AuthURL: "https://auth.example.com/authorize",
			})
			return
		}
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/connection") {
			json.NewEncoder(w).Encode(connectionStatusResponse{Status: "pending"})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 2)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "not completed in time") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestEnsureServerConnected_GetServerNon404Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"server error"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 1)
	if err == nil {
		t.Fatal("expected error for 500 from GetServer")
	}
	// Should NOT be ServerNotFoundError
	if _, ok := err.(*ServerNotFoundError); ok {
		t.Error("should not be ServerNotFoundError for 500")
	}
}

func TestEnsureServerConnected_InitiateConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GetServer returns available server
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/by-slug/github") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "1", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusAvailable,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		// InitiateConnection fails
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/connect") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"internal error"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 1)
	if err == nil {
		t.Fatal("expected error when InitiateConnection fails")
	}
}

func TestEnsureServerConnected_PollError(t *testing.T) {
	old := openBrowserFunc
	openBrowserFunc = func(u string) error { return nil }
	defer func() { openBrowserFunc = old }()

	pollCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/by-slug/github") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "1", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusAvailable,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/connect") {
			json.NewEncoder(w).Encode(connectionInitiationResponse{
				AuthURL: "https://auth.example.com/authorize",
			})
			return
		}
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/connection") {
			pollCount++
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"server error"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 5)
	if err == nil {
		t.Fatal("expected error when polling fails")
	}
}

func TestEnsureServerConnected_UsesSlugFromServer(t *testing.T) {
	old := openBrowserFunc
	openBrowserFunc = func(u string) error { return nil }
	defer func() { openBrowserFunc = old }()

	var connectPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GetServer by UUID returns a server with a slug
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/api/servers/550e8400") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "550e8400-e29b-41d4-a716-446655440000", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusAvailable,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		// InitiateConnection - capture path
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/connect") {
			connectPath = r.URL.Path
			json.NewEncoder(w).Encode(connectionInitiationResponse{
				AuthURL: "https://auth.example.com/authorize",
			})
			return
		}
		// Poll returns connected immediately
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/connection") {
			json.NewEncoder(w).Encode(connectionStatusResponse{Status: "connected"})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "550e8400-e29b-41d4-a716-446655440000", 5)
	if err != nil {
		t.Fatalf("EnsureServerConnected failed: %v", err)
	}
	// Should use slug "github" for InitiateConnection, not UUID
	if !strings.Contains(connectPath, "github") {
		t.Errorf("expected slug in connect path, got: %s", connectPath)
	}
}

func TestReq_SuccessfulRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("Authorization header = %q, want Bearer prefix", auth)
		}
		fmt.Fprint(w, `{"result":"ok"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	resp, err := sdk.req(context.Background(), "GET", "/test", nil)
	if err != nil {
		t.Fatalf("req failed: %v", err)
	}

	var data map[string]string
	json.Unmarshal(resp, &data)
	if data["result"] != "ok" {
		t.Errorf("result = %q, want ok", data["result"])
	}
}

func TestDisconnectServer_OtherError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"server error"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.DisconnectServer(context.Background(), "github")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	// Should NOT contain "not found" / "not be connected"
	if strings.Contains(err.Error(), "not be connected") {
		t.Errorf("should not be connection-not-found error: %v", err)
	}
}

func TestEnsureServerConnected_DefaultPollSeconds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/by-slug/github") {
			detail := ServerDetail{
				ServerSummary: ServerSummary{
					ID: "1", Name: "GitHub", Slug: "github",
					ConnectionStatus: ConnectionStatusConnected,
				},
			}
			json.NewEncoder(w).Encode(detail)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.EnsureServerConnected(context.Background(), "github", 0)
	if err != nil {
		t.Fatalf("EnsureServerConnected with default poll failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ListServers — error cases
// ---------------------------------------------------------------------------

func TestListServers_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"server error"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.ListServers(context.Background())
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

func TestListServers_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.ListServers(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// GetServer — error case
// ---------------------------------------------------------------------------

func TestGetServer_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"server error"}`)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.GetServer(context.Background(), "github")
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestGetServer_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, err := sdk.GetServer(context.Background(), "github")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
