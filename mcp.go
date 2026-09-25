package barndoor

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The platform serves MCP alongside REST, on the same host with the
// organization in front of it. MCP is a different protocol, so none of this is
// in the OpenAPI document.

// McpOptions is where to connect and who to say you are.
type McpOptions struct {
	// BaseURL is the host serving MCP, WITHOUT the organization subdomain.
	// Defaults to the client's API base URL, since one vhost serves both.
	BaseURL string
	// SessionID correlates every call in one session in Barndoor's audit trail.
	SessionID string
	// ClientName and ClientVersion are reported during initialisation.
	ClientName    string
	ClientVersion string
}

func (o McpOptions) implementation() *mcp.Implementation {
	name, version := o.ClientName, o.ClientVersion
	if name == "" {
		name = "barndoor-sdk"
	}
	if version == "" {
		version = "2.0.0"
	}
	return &mcp.Implementation{Name: name, Version: version}
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// McpConnectionParams returns the URL and headers to reach MCP without opening
// a connection, for handing to another framework rather than using NewMcpClient.
//
// Omit serverIDOrSlug for the universal endpoint (/mcp), which exposes every
// server the caller can reach; pass one to connect to a single server
// (/mcp/<slug>). A server id is accepted and exchanged for its slug.
//
// The headers carry a bearer token. Treat them as a secret.
func McpConnectionParams(ctx context.Context, client *Client, orgSlug, serverIDOrSlug string, opts McpOptions) (string, map[string]string, error) {
	if orgSlug == "" {
		return "", nil, fmt.Errorf("an organization slug is required: it selects the tenant serving MCP")
	}
	if client == nil || client.tokenSource == nil {
		return "", nil, fmt.Errorf("client was not built by New()")
	}

	base := opts.BaseURL
	if base == "" {
		resolved, err := client.Configuration.ServerURLWithContext(ctx, "")
		if err != nil {
			return "", nil, err
		}
		base = resolved
	}

	endpoint, err := withOrganization(base, orgSlug)
	if err != nil {
		return "", nil, err
	}
	endpoint.Path = "/mcp"
	if serverIDOrSlug != "" {
		slug, err := resolveSlug(ctx, client, serverIDOrSlug)
		if err != nil {
			return "", nil, err
		}
		endpoint.Path = "/mcp/" + slug
	}

	// The same source the generated operations use, so an MCP session cannot
	// end up on a different or stale credential.
	token, err := client.tokenSource.Token()
	if err != nil {
		return "", nil, fmt.Errorf("mcp: no credential: %w", err)
	}

	sessionID := opts.SessionID
	if sessionID == "" {
		if sessionID, err = newSessionID(); err != nil {
			return "", nil, err
		}
	}

	return endpoint.String(), map[string]string{
		"Accept":                "application/json, text/event-stream",
		"Authorization":         "Bearer " + token.AccessToken,
		"x-barndoor-session-id": sessionID,
	}, nil
}

// NewMcpClient opens a connected MCP session, already through initialize, so
// callers use the MCP API directly. Close it with session.Close().
func NewMcpClient(ctx context.Context, client *Client, orgSlug, serverIDOrSlug string, opts McpOptions) (*mcp.ClientSession, error) {
	endpoint, headers, err := McpConnectionParams(ctx, client, orgSlug, serverIDOrSlug, opts)
	if err != nil {
		return nil, err
	}

	// The transport takes no headers of its own; authentication rides on the
	// http client it is handed, as it does in the Python SDK.
	transport := &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: headerTransport{headers: headers, next: http.DefaultTransport}},
	}
	return mcp.NewClient(opts.implementation(), nil).Connect(ctx, transport, nil)
}

type headerTransport struct {
	headers map[string]string
	next    http.RoundTripper
}

func (h headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for name, value := range h.headers {
		clone.Header.Set(name, value)
	}
	return h.next.RoundTrip(clone)
}

// withOrganization puts the tenant in front of the host:
// platform.example.com -> acme.platform.example.com
func withOrganization(base, orgSlug string) (*url.URL, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("%q has no host to prefix", base)
	}
	host := orgSlug + "." + parsed.Hostname()
	if port := parsed.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	parsed.Host = host
	return parsed, nil
}

// resolveSlug exchanges a server id for its slug; a value that is not a UUID is
// already one.
func resolveSlug(ctx context.Context, client *Client, serverIDOrSlug string) (string, error) {
	if !uuidPattern.MatchString(serverIDOrSlug) {
		return serverIDOrSlug, nil
	}
	server, resp, err := client.Registry.GetMcpServer(ctx, serverIDOrSlug).Execute()
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	if err != nil {
		return "", fmt.Errorf("mcp: resolving server %s: %w", serverIDOrSlug, err)
	}
	if server.Slug == "" {
		return "", fmt.Errorf("mcp: server %s has no slug", serverIDOrSlug)
	}
	return server.Slug, nil
}

// newSessionID is a v4 UUID without a dependency for it.
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var sb strings.Builder
	fmt.Fprintf(&sb, "%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	return sb.String(), nil
}
