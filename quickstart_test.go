package barndoor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// EnsureServerConnectedQuickstart
// ---------------------------------------------------------------------------

func TestEnsureServerConnectedQuickstart_AlreadyConnected(t *testing.T) {
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

	err := EnsureServerConnectedQuickstart(context.Background(), sdk, "github", 5)
	if err != nil {
		t.Fatalf("EnsureServerConnectedQuickstart failed: %v", err)
	}
}

func TestEnsureServerConnectedQuickstart_ServerNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := EnsureServerConnectedQuickstart(context.Background(), sdk, "nonexistent", 1)
	if err == nil {
		t.Fatal("expected error for server not found")
	}
}

func TestEnsureServerConnectedQuickstart_DefaultTimeout(t *testing.T) {
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

	// timeout <= 0 defaults to 90
	err := EnsureServerConnectedQuickstart(context.Background(), sdk, "github", 0)
	if err != nil {
		t.Fatalf("EnsureServerConnectedQuickstart failed: %v", err)
	}
}

func TestEnsureServerConnectedQuickstart_OtherError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server error"})
	}))
	defer server.Close()

	sdk := newTestSDKNoRetry(t, server)
	defer sdk.Close()

	err := EnsureServerConnectedQuickstart(context.Background(), sdk, "github", 1)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

// ---------------------------------------------------------------------------
// MakeMCPConnectionParams
// ---------------------------------------------------------------------------

func TestMakeMCPConnectionParams_Success(t *testing.T) {
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

	params, mcpURL, err := MakeMCPConnectionParams(context.Background(), sdk, "github")
	if err != nil {
		t.Fatalf("MakeMCPConnectionParams failed: %v", err)
	}

	if params == nil {
		t.Fatal("params should not be nil")
	}
	if params.Transport != "streamable-http" {
		t.Errorf("Transport = %q, want streamable-http", params.Transport)
	}
	if params.Headers["Authorization"] == "" {
		t.Error("Authorization header should be set")
	}
	if params.Headers["x-barndoor-session-id"] == "" {
		t.Error("session ID header should be set")
	}
	if mcpURL == "" {
		t.Error("mcpURL should not be empty")
	}
	if !strings.Contains(mcpURL, "github") {
		t.Errorf("mcpURL should contain server slug: %q", mcpURL)
	}
}

func TestMakeMCPConnectionParams_ServerNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	_, _, err := MakeMCPConnectionParams(context.Background(), sdk, "nonexistent")
	if err == nil {
		t.Fatal("expected error for server not found")
	}
	if _, ok := err.(*ServerNotFoundError); !ok {
		t.Errorf("expected ServerNotFoundError, got %T", err)
	}
}

func TestMakeMCPConnectionParams_OtherHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server error"})
	}))
	defer server.Close()

	sdk := newTestSDKNoRetry(t, server)
	defer sdk.Close()

	_, _, err := MakeMCPConnectionParams(context.Background(), sdk, "github")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	// Should NOT be ServerNotFoundError (that's for 404)
	if _, ok := err.(*ServerNotFoundError); ok {
		t.Error("should not be ServerNotFoundError for 500")
	}
}

func TestMakeMCPConnectionParams_EmptySlugFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		detail := ServerDetail{
			ServerSummary: ServerSummary{
				ID:               "1",
				Name:             "Test Server",
				Slug:             "", // empty slug
				ConnectionStatus: ConnectionStatusConnected,
			},
		}
		json.NewEncoder(w).Encode(detail)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	params, mcpURL, err := MakeMCPConnectionParams(context.Background(), sdk, "test-server")
	if err != nil {
		t.Fatalf("MakeMCPConnectionParams failed: %v", err)
	}

	// Should fall back to the input identifier
	if !strings.Contains(mcpURL, "test-server") {
		t.Errorf("mcpURL should contain input identifier: %q", mcpURL)
	}
	if params.Transport != "streamable-http" {
		t.Errorf("Transport = %q", params.Transport)
	}
}

func TestMakeMCPConnectionParams_NoToken(t *testing.T) {
	t.Setenv("BARNDOOR_ENV", "test")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		detail := ServerDetail{
			ServerSummary: ServerSummary{
				ID: "1", Name: "GitHub", Slug: "github",
				ConnectionStatus: ConnectionStatusConnected,
			},
		}
		json.NewEncoder(w).Encode(detail)
	}))
	defer server.Close()

	// SDK with no token (but EnsureValidToken is bypassed in test env)
	sdk, err := NewBarndoorSDK(server.URL, nil)
	if err != nil {
		t.Fatalf("NewBarndoorSDK failed: %v", err)
	}
	defer sdk.Close()
	sdk.tokenValidated = true

	_, _, err = MakeMCPConnectionParams(context.Background(), sdk, "github")
	if err == nil {
		t.Fatal("expected error when no token set")
	}
}
