//go:build ignore

// List the MCP servers registered in your organization.
//
// Run: BARNDOOR_API_KEY=bdai_… go run examples/list_mcp_servers.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk/v2"
)

func main() {
	key := os.Getenv("BARNDOOR_API_KEY")
	if key == "" {
		log.Fatal("Set BARNDOOR_API_KEY")
	}

	client := barndoor.New(barndoor.StaticToken(key))

	page, resp, err := client.Registry.ListMcpServers(context.Background()).Limit(10).Execute()
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	for _, server := range page.Data {
		fmt.Printf("%s  (%s)\n", server.Name, server.Slug)
	}
	fmt.Printf("\n%d of %d server(s)\n", len(page.Data), page.Pagination.Total)
}
