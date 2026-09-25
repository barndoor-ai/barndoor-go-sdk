//go:build ignore

// Authenticate with client credentials rather than an API key.
//
// The token is obtained on the first request and refreshed before it expires —
// there is nothing to schedule or cache yourself.
//
// Run: BARNDOOR_CLIENT_ID=… BARNDOOR_CLIENT_SECRET=… go run examples/machine_to_machine.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk/v2"
)

func main() {
	clientID := os.Getenv("BARNDOOR_CLIENT_ID")
	clientSecret := os.Getenv("BARNDOOR_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("Set BARNDOOR_CLIENT_ID and BARNDOOR_CLIENT_SECRET")
	}

	ctx := context.Background()
	auth := barndoor.ClientCredentials(ctx, barndoor.ClientCredentialsOptions{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	client := barndoor.New(auth)

	page, resp, err := client.Registry.ListMcpServers(ctx).Limit(5).Execute()
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	names := make([]string, 0, len(page.Data))
	for _, server := range page.Data {
		names = append(names, server.Name)
	}
	fmt.Println(names)
}
