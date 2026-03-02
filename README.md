# Barndoor Go SDK

A lightweight, **framework-agnostic** Go client for the Barndoor Platform REST APIs and Model Context Protocol (MCP) servers.

The SDK removes boiler-plate around:

* Secure, offline-friendly **authentication to Barndoor** (interactive PKCE flow + token caching).
* **Server registry** – list, inspect and connect third-party providers (Salesforce, Notion, Slack …).
* **Managed Connector Proxy** – build ready-to-use connection parameters for any LLM/agent framework without importing Barndoor-specific adapters.

---

## How it works

The SDK orchestrates a multi-step flow to connect your code to third-party services:

```
You → Barndoor Auth (get JWT) → Registry API (with JWT) → MCP Proxy (with JWT) → Third-party service
```

1. **Authentication**: You log in via Barndoor to get a JWT token
2. **Registry API**: Using the JWT, query available MCP servers and manage OAuth connections
3. **MCP Proxy**: Stream requests through Barndoor's proxy with the JWT for authorization
4. **Third-party service**: The proxy forwards your requests to Salesforce, Notion, etc.

This architecture provides secure, managed access to external services without handling OAuth flows or storing third-party credentials in your code.

---

## Installation

```bash
go get github.com/barndoor-ai/barndoor-go-sdk
```

Go 1.22+ is required.

---

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk"
)

func main() {
	ctx := context.Background()

	// 1. Login (handles OAuth PKCE flow + token caching)
	sdk, err := barndoor.LoginInteractive(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer sdk.Close()

	// 2. Ensure server is connected (launches OAuth if needed)
	err = barndoor.EnsureServerConnectedQuickstart(ctx, sdk, "salesforce", 0)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Get connection parameters for your MCP client
	params, mcpURL, err := barndoor.MakeMCPConnectionParams(ctx, sdk, "salesforce")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("MCP URL:", mcpURL)
	fmt.Println("Transport:", params.Transport)
	fmt.Println("Headers:", params.Headers)
}
```

---

## Manual setup

For programmatic use (e.g., in agents), create an SDK directly with a known JWT:

```go
sdk, err := barndoor.NewBarndoorSDK("https://myorg.platform.barndoor.ai", &barndoor.SDKOptions{
    Token: myJWT,
})
if err != nil {
    log.Fatal(err)
}
defer sdk.Close()
```

Or authenticate later:

```go
sdk, err := barndoor.NewBarndoorSDK("https://myorg.platform.barndoor.ai", nil)
if err != nil {
    log.Fatal(err)
}
defer sdk.Close()

err = sdk.Authenticate(ctx, myJWT)
```

---

## Environment configuration

The SDK automatically configures endpoints based on `BARNDOOR_ENV`. Just set your credentials:

```bash
export AGENT_CLIENT_ID=your_client_id
export AGENT_CLIENT_SECRET=your_client_secret
```

See [`env.example`](./env.example) for the full list of options.

| Variable | Description | Default |
|---|---|---|
| `BARNDOOR_ENV` | Environment name (`production`, `uat`, `dev`, `enterprise-production`, etc.) | `production` |
| `AGENT_CLIENT_ID` | OAuth client ID | — |
| `AGENT_CLIENT_SECRET` | OAuth client secret | — |
| `BARNDOOR_URL` / `BARNDOOR_API` | API base URL override | per-environment default |
| `AUTH_URL` | Auth issuer override | per-environment default |
| `BARNDOOR_REDIRECT_HOST` | OAuth callback host | `127.0.0.1` |

---

## Authentication workflow

Barndoor APIs expect a **user JWT** issued by your Barndoor tenant. The SDK offers two ways to obtain and store a token:

| Option | Function | When to use |
|---|---|---|
| Interactive login | `barndoor.LoginInteractive(ctx, nil)` | Development, CLI tools, scripts |
| Direct token | `barndoor.NewBarndoorSDK(url, &SDKOptions{Token: jwt})` | Agents, services with pre-obtained tokens |

The interactive flow:

1. Spins up a tiny localhost callback server (default port 52765).
2. Opens the system browser to Barndoor.
3. Exchanges the returned authorization code for a JWT via PKCE.
4. Persists the token to `~/.barndoor/token.json` (0600 permissions).

The cached token is checked on every run; if it is expired or revoked, a new browser flow is launched.

**Note:** The OAuth default callback uses port 52765. Make sure to register this callback in your Barndoor Agent configuration. As some machines resolve `localhost` to `127.0.0.1`, we recommend having two callback entries:
```
http://localhost:52765/cb
http://127.0.0.1:52765/cb
```

### Using a custom OAuth callback port

If port `52765` is blocked (or you prefer another), register the new callback URL and pass the port in options:

```go
sdk, err := barndoor.LoginInteractive(ctx, &barndoor.LoginInteractiveOptions{
    Port: 60000,
})
```

---

## Using the Registry API

```go
// List all MCP servers available to the current user
servers, err := sdk.ListServers(ctx)
for _, s := range servers {
    fmt.Printf("%s (%s)\n", s.Slug, s.ConnectionStatus)
}

// Get detailed metadata
server, err := sdk.GetServer(ctx, "notion")

// Initiate an OAuth connection (returns auth URL for browser)
authURL, err := sdk.InitiateConnection(ctx, "notion", "")

// Check connection status
status, err := sdk.GetConnectionStatus(ctx, "notion")

// Disconnect from a server
err = sdk.DisconnectServer(ctx, "notion")
```

---

## MCP connection

Once a server is **connected**, build connection parameters for any MCP client:

```go
params, mcpURL, err := barndoor.MakeMCPConnectionParams(ctx, sdk, "notion")

fmt.Println(params.URL)       // https://myorg.mcp.barndoor.ai/mcp/notion
fmt.Println(params.Transport) // streamable-http
fmt.Println(params.Headers)   // Authorization, x-barndoor-session-id
```

The returned `MCPConnectionParams` struct contains `URL`, `Transport`, and `Headers` — ready to plug into any HTTP/SSE/WebSocket MCP client.

---

## Error handling

The SDK provides a typed error hierarchy. Use type assertions to handle specific cases:

```go
servers, err := sdk.ListServers(ctx)
if err != nil {
    switch e := err.(type) {
    case *barndoor.HTTPError:
        fmt.Printf("HTTP %d: %s\n", e.StatusCode, e.Message)
    case *barndoor.TokenError:
        fmt.Println("Token error — re-authenticate")
    case *barndoor.ConnectionError:
        fmt.Printf("Connection failed to %s: %s\n", e.URL, e.Message)
    case *barndoor.ConfigurationError:
        fmt.Println("Config error:", e.Message)
    case *barndoor.ServerNotFoundError:
        fmt.Println("Server not found:", e.ServerIdentifier)
    default:
        fmt.Println(err)
    }
}
```

---

## API reference

Full godoc documentation is available via:

```bash
go doc github.com/barndoor-ai/barndoor-go-sdk
```

### Key types

| Type | Description |
|---|---|
| `BarndoorSDK` | Main client — holds token, HTTP client, base URL |
| `SDKOptions` | Constructor options (token, timeout, retries) |
| `ServerSummary` | Server list entry (ID, name, slug, connection status) |
| `ServerDetail` | Extended server info (embeds `ServerSummary` + URL) |
| `MCPConnectionParams` | MCP connection config (URL, transport, headers) |
| `LoginInteractiveOptions` | Options for the interactive PKCE login flow |

### Key functions

| Function | Description |
|---|---|
| `NewBarndoorSDK(url, opts)` | Create an SDK instance |
| `LoginInteractive(ctx, opts)` | Interactive OAuth PKCE login |
| `MakeMCPConnectionParams(ctx, sdk, slug)` | Build MCP connection params |
| `EnsureServerConnectedQuickstart(ctx, sdk, slug, timeout)` | Connect + poll with logging |
| `GetStaticConfig()` | Read environment config |

### SDK methods

| Method | Description |
|---|---|
| `Authenticate(ctx, token)` | Set/validate a JWT |
| `ListServers(ctx)` | List all available MCP servers |
| `GetServer(ctx, id)` | Get server details (by UUID or slug) |
| `InitiateConnection(ctx, id, returnURL)` | Start OAuth connection flow |
| `GetConnectionStatus(ctx, id)` | Check connection status |
| `DisconnectServer(ctx, id)` | Disconnect from a server |
| `EnsureServerConnected(ctx, id, pollSeconds)` | Connect + poll until ready |
| `Close()` | Release resources |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup instructions.
