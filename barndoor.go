// Package barndoor provides a Go SDK for the Barndoor Platform API.
//
// The SDK provides methods for:
//   - User authentication via OAuth/PKCE flows
//   - MCP server discovery and management
//   - OAuth connection handling for third-party providers
//   - Agent credential exchange
//   - Token lifecycle management (storage, validation, refresh)
//
// # Quick Start
//
// The simplest way to get started is with [LoginInteractive], which handles
// the full OAuth login flow:
//
//	sdk, err := barndoor.LoginInteractive(ctx, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sdk.Close()
//
//	servers, err := sdk.ListServers(ctx)
//
// # Manual Setup
//
// For programmatic use (e.g., in agents), create an SDK directly:
//
//	sdk, err := barndoor.NewBarndoorSDK("https://myorg.platform.barndoor.ai", &barndoor.SDKOptions{
//	    Token: myJWT,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sdk.Close()
//
// # Configuration
//
// The SDK reads configuration from environment variables:
//   - BARNDOOR_ENV: environment name (production, uat, dev, enterprise-production, etc.)
//   - AGENT_CLIENT_ID: OAuth client ID
//   - AGENT_CLIENT_SECRET: OAuth client secret
//   - BARNDOOR_API or BARNDOOR_URL: API base URL override
//
// Auth configuration (issuer, audience, base URL) is baked in per environment.
// See [AuthConfig] for the full list.
package barndoor

// Version is the semantic version of the barndoor-go-sdk.
const Version = "0.1.0"
