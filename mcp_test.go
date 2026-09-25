package barndoor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/barndoor-ai/barndoor-go-sdk/v2/api"
)

func TestWithOrganization(t *testing.T) {
	cases := []struct{ base, org, want string }{
		{"https://platform.barndoor.ai", "acme", "https://acme.platform.barndoor.ai"},
		{"https://platform.barndoordev.com", "acme", "https://acme.platform.barndoordev.com"},
		{"http://localhost:8080", "acme", "http://acme.localhost:8080"},
	}
	for _, tc := range cases {
		got, err := withOrganization(tc.base, tc.org)
		if err != nil {
			t.Fatalf("%s: %v", tc.base, err)
		}
		if got.String() != tc.want {
			t.Errorf("withOrganization(%q, %q) = %q, want %q", tc.base, tc.org, got, tc.want)
		}
	}
}

func TestWithOrganizationRejectsAHostlessBase(t *testing.T) {
	if _, err := withOrganization("not-a-url", "acme"); err == nil {
		t.Error("want an error for a base with no host")
	}
}

func TestMcpConnectionParams(t *testing.T) {
	client := New(StaticToken("tok"), WithEnvironment(Environment{BaseURL: "https://platform.example.test"}))

	url, headers, err := McpConnectionParams(context.Background(), client, "acme", "", McpOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://acme.platform.example.test/mcp"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
	if got := headers["Authorization"]; got != "Bearer tok" {
		t.Errorf("Authorization = %q — the MCP session must reuse the REST credential", got)
	}
	if got := headers["Accept"]; got != "application/json, text/event-stream" {
		t.Errorf("Accept = %q", got)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).
		MatchString(headers["x-barndoor-session-id"]) {
		t.Errorf("session id %q is not a v4 UUID", headers["x-barndoor-session-id"])
	}
}

// Naming a server connects to just that one; omitting it is the universal
// endpoint. The Python SDK only has the universal form — see sdk/README.md.
func TestMcpConnectionParamsNamesASingleServer(t *testing.T) {
	client := New(StaticToken("tok"), WithEnvironment(Environment{BaseURL: "https://platform.example.test"}))

	url, _, err := McpConnectionParams(context.Background(), client, "acme", "gmail", McpOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://acme.platform.example.test/mcp/gmail"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
}

// A UUID is exchanged for the slug the MCP path needs, so a caller can pass
// whichever identifier they are holding.
func TestMcpConnectionParamsResolvesAnIdToItsSlug(t *testing.T) {
	// Built from the generated model rather than hand-written JSON, so the
	// fixture cannot fall behind the spec's required properties.
	fixture := api.NewServerResponseWithDefaults()
	fixture.Id = "11111111-1111-1111-1111-111111111111"
	fixture.Slug = "gmail"
	// Required properties the zero value leaves nil, which MarshalJSON omits.
	fixture.Scopes = []string{}
	fixture.PublishBlockers = []api.PublishBlocker{}
	fixture.CascadedFields = []string{}
	fixture.Meta = map[string]any{}
	fixture.ToolsFetchError = map[string]any{}
	fixture.McpServerDirectory = *api.NewMCPServerDirectoryBaseWithDefaults()
	fixture.McpServerDirectory.ProviderOptions = map[string]any{}
	fixture.McpServerDirectory.Scopes = []string{}
	fixture.McpServerDirectory.OauthMetadata = map[string]any{}
	fixture.McpServerDirectory.ProtectedResourceMetadata = map[string]any{}
	fixture.McpServerDirectory.Meta = map[string]any{}
	fixture.McpServerDirectory.AuthParams = map[string]any{}
	fixture.McpServerDirectory.CredentialSchema = map[string]any{}
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}

	var asked string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client := New(StaticToken("tok"), WithEnvironment(Environment{BaseURL: server.URL}))
	mcpURL, _, err := McpConnectionParams(context.Background(), client,
		"acme", "11111111-1111-1111-1111-111111111111", McpOptions{BaseURL: "https://platform.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(mcpURL, "/mcp/gmail") {
		t.Errorf("url = %q, want it to end in the resolved slug", mcpURL)
	}
	if !strings.Contains(asked, "11111111-1111-1111-1111-111111111111") {
		t.Errorf("did not look the id up; asked for %q", asked)
	}
}

func TestMcpConnectionParamsRequiresAnOrganization(t *testing.T) {
	client := New(StaticToken("tok"))
	if _, _, err := McpConnectionParams(context.Background(), client, "", "", McpOptions{}); err == nil {
		t.Error("want an error without an organization slug")
	}
}

func TestMcpConnectionParamsHonoursOptions(t *testing.T) {
	client := New(StaticToken("tok"))
	url, headers, err := McpConnectionParams(context.Background(), client, "acme", "",
		McpOptions{BaseURL: "https://other.example.test", SessionID: "fixed-session"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://acme.other.example.test/mcp"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
	if headers["x-barndoor-session-id"] != "fixed-session" {
		t.Errorf("session id = %q", headers["x-barndoor-session-id"])
	}
}

func TestNewSessionIDIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id, err := newSessionID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
	}
}

func TestMcpOptionsDefaultImplementation(t *testing.T) {
	impl := McpOptions{}.implementation()
	if impl.Name != "barndoor-sdk" || impl.Version == "" {
		t.Errorf("implementation = %+v", impl)
	}
	custom := McpOptions{ClientName: "mine", ClientVersion: "9.9.9"}.implementation()
	if custom.Name != "mine" || custom.Version != "9.9.9" {
		t.Errorf("implementation = %+v", custom)
	}
}

// The headers must reach the transport, or the MCP server sees an
// unauthenticated request.
func TestHeaderTransportAppliesEveryHeader(t *testing.T) {
	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer server.Close()

	client := &http.Client{Transport: headerTransport{
		headers: map[string]string{"Authorization": "Bearer tok", "x-barndoor-session-id": "s"},
		next:    http.DefaultTransport,
	}}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if got.Get("Authorization") != "Bearer tok" || got.Get("x-barndoor-session-id") != "s" {
		t.Errorf("headers = %v", got)
	}
}
