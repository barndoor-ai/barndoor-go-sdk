//go:build ignore

// Connect to Barndoor's MCP endpoint and list the tools it exposes.
//
// Every call is authenticated with the same credentials as the REST client and
// recorded in your organization's audit trail.
//
// Run: BARNDOOR_API_KEY=bdai_… BARNDOOR_ORG=acme go run examples/mcp_client.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk/v2"
)

func main() {
	key, org := os.Getenv("BARNDOOR_API_KEY"), os.Getenv("BARNDOOR_ORG")
	if key == "" || org == "" {
		log.Fatal("Set BARNDOOR_API_KEY and BARNDOOR_ORG")
	}
	ctx := context.Background()

	client := barndoor.New(barndoor.StaticToken(key))
	session, err := barndoor.NewMcpClient(ctx, client, org, "", barndoor.McpOptions{
		ClientName:    "mcp-client-example",
		ClientVersion: "1.0.0",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close() //nolint:errcheck

	result, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, tool := range result.Tools {
		description := tool.Description
		if description == "" {
			description = "no description"
		}
		fmt.Printf("%s — %s\n", tool.Name, description)
	}
}
