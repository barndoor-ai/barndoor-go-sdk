//go:build ignore

// Get MCP connection details without opening a connection, so another
// framework — CrewAI, LangChain, your own client — can do the connecting.
//
// Run: BARNDOOR_API_KEY=bdai_… BARNDOOR_ORG=acme go run examples/connection_params.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk/v2"
)

func main() {
	key, org := os.Getenv("BARNDOOR_API_KEY"), os.Getenv("BARNDOOR_ORG")
	if key == "" || org == "" {
		log.Fatal("Set BARNDOOR_API_KEY and BARNDOOR_ORG")
	}

	client := barndoor.New(barndoor.StaticToken(key))
	url, headers, err := barndoor.McpConnectionParams(context.Background(), client, org, "", barndoor.McpOptions{})
	if err != nil {
		log.Fatal(err)
	}

	// `headers` carries a bearer token. Treat it as a secret.
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Println("url:", url)
	fmt.Println("headers:", strings.Join(names, ", "))
}
