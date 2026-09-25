// Command barndoor-login is an interactive login from a terminal, matching the
// Python SDK's `barndoor-login` console script.
//
// It is a separate main package so that importing the SDK never drags in an
// HTTP server.
package main

import (
	"context"
	"fmt"
	"os"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk/v2"
)

func main() {
	token, err := barndoor.LoginInteractive(context.Background(), barndoor.LoginOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	refresh := token.RefreshToken
	if refresh == "" {
		refresh = "<none returned>"
	}
	fmt.Printf("\nSigned in. Keep the refresh token somewhere your app can read it:\n  refresh_token: %s\n", refresh)
}
