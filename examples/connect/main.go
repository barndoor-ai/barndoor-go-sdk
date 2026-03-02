// Command connect demonstrates using the Barndoor Go SDK to authenticate,
// list available MCP servers, and build connection parameters for one.
//
// Usage:
//
//	export BARNDOOR_ENV=production          # or uat, dev, etc.
//	export AGENT_CLIENT_ID=your_client_id
//	export AGENT_CLIENT_SECRET=your_client_secret
//	go run ./examples/connect [server-slug]
//
// If a server slug is provided (e.g. "github"), the program will ensure
// the server is connected and print MCP connection parameters.
// Otherwise it lists all available servers.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk"
)

func main() {
	ctx := context.Background()

	// LoginInteractive handles the full OAuth PKCE flow:
	//   1. Checks for a cached token in ~/.barndoor/token.json
	//   2. Opens the browser for authentication if needed
	//   3. Exchanges the authorization code for a JWT
	//   4. Returns a ready-to-use SDK client
	sdk, err := barndoor.LoginInteractive(ctx, nil)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	defer sdk.Close()

	fmt.Println("Authenticated to", sdk.Base)

	// If a server slug was provided, connect to it and print MCP params.
	if len(os.Args) > 1 {
		slug := os.Args[1]
		connectAndPrint(ctx, sdk, slug)
		return
	}

	// Otherwise list all available servers.
	listServers(ctx, sdk)
}

func listServers(ctx context.Context, sdk *barndoor.BarndoorSDK) {
	servers, err := sdk.ListServers(ctx)
	if err != nil {
		log.Fatalf("Failed to list servers: %v", err)
	}

	fmt.Printf("\nAvailable servers (%d):\n", len(servers))
	for _, s := range servers {
		provider := ""
		if s.Provider != nil {
			provider = *s.Provider
		}
		fmt.Printf("  %-20s %-15s %s\n", s.Slug, s.ConnectionStatus, provider)
	}
}

func connectAndPrint(ctx context.Context, sdk *barndoor.BarndoorSDK, slug string) {
	// EnsureServerConnectedQuickstart handles the full connection flow:
	//   - If the server is already connected, returns immediately
	//   - If not, initiates OAuth, opens the browser, and polls until connected
	if err := barndoor.EnsureServerConnectedQuickstart(ctx, sdk, slug, 0); err != nil {
		log.Fatalf("Failed to connect to %s: %v", slug, err)
	}

	// Build framework-agnostic MCP connection parameters.
	params, mcpURL, err := barndoor.MakeMCPConnectionParams(ctx, sdk, slug)
	if err != nil {
		log.Fatalf("Failed to build MCP params: %v", err)
	}

	fmt.Printf("\nMCP connection parameters for %s:\n", slug)
	fmt.Println("  URL:      ", mcpURL)
	fmt.Println("  Transport:", params.Transport)
	fmt.Println("  Headers:")
	for k, v := range params.Headers {
		if k == "Authorization" {
			fmt.Printf("    %s: Bearer <redacted>\n", k)
			continue
		}
		fmt.Printf("    %s: %s\n", k, v)
	}
}
