package barndoor_test

import (
	"context"
	"fmt"
	"log"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk"
)

func ExampleNewBarndoorSDK() {
	sdk, err := barndoor.NewBarndoorSDK("https://myorg.platform.barndoor.ai", &barndoor.SDKOptions{
		Token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sdk.Close()

	fmt.Println("SDK initialized for", sdk.Base)
}

func ExampleGetStaticConfig() {
	cfg := barndoor.GetStaticConfig()
	fmt.Println("Environment:", cfg.Environment)
	fmt.Println("Auth Issuer:", cfg.AuthIssuer)
}

func ExampleLoginInteractive() {
	ctx := context.Background()

	// LoginInteractive handles the full OAuth PKCE flow:
	// 1. Checks for a cached token
	// 2. Opens browser for auth if needed
	// 3. Exchanges code for JWT
	// 4. Returns a ready-to-use SDK
	sdk, err := barndoor.LoginInteractive(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer sdk.Close()

	servers, err := sdk.ListServers(ctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, s := range servers {
		fmt.Printf("%s (%s)\n", s.Name, s.ConnectionStatus)
	}
}

func ExampleMakeMCPConnectionParams() {
	ctx := context.Background()

	sdk, err := barndoor.NewBarndoorSDK("https://myorg.platform.barndoor.ai", &barndoor.SDKOptions{
		Token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sdk.Close()

	params, mcpURL, err := barndoor.MakeMCPConnectionParams(ctx, sdk, "github")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("MCP URL:", mcpURL)
	fmt.Println("Transport:", params.Transport)
}
