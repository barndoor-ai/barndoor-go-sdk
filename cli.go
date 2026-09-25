package barndoor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

// Loopback only. A public redirect would hand the authorization code to
// whoever controls that host.
const (
	loginHost        = "127.0.0.1"
	DefaultLoginPort = 8765
)

// LoginOptions configures LoginInteractive.
type LoginOptions struct {
	// Port for the loopback redirect. Zero means DefaultLoginPort. It must
	// match a redirect URI registered for ClientID.
	Port int
	// ClientID defaults to "barndoor-cli".
	ClientID string
	// Issuer defaults to the environment's, or production.
	Issuer string
	// Timeout for the whole flow. Zero means five minutes.
	Timeout time.Duration
	// OpenBrowser is called with the authorization URL. Zero value opens the
	// system browser; supply your own to print it instead.
	OpenBrowser func(url string) error
}

// LoginInteractive runs the browser flow and returns the token, refresh token
// included, so the caller decides where to keep it.
//
// It binds a port, which is why importing this SDK must never start a server on
// its own: nothing here runs unless a caller asks for it.
func LoginInteractive(ctx context.Context, opts LoginOptions) (*oauth2.Token, error) {
	port := opts.Port
	if port == 0 {
		port = DefaultLoginPort
	}
	clientID := opts.ClientID
	if clientID == "" {
		clientID = "barndoor-cli"
	}
	issuer := opts.Issuer
	if issuer == "" {
		if env, ok := EnvironmentFromEnv(); ok {
			issuer = env.Issuer
		} else {
			issuer = ProductionIssuer
		}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	open := opts.OpenBrowser
	if open == nil {
		open = openBrowser
	}

	redirectURI := fmt.Sprintf("http://%s:%d/callback", loginHost, port)
	request, err := StartAuthorizationCode(clientID, redirectURI, issuer, nil)
	if err != nil {
		return nil, err
	}

	// Bound before the browser opens, so a redirect cannot arrive before
	// anything is listening.
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", loginHost, port))
	if err != nil {
		return nil, fmt.Errorf("login: cannot listen on %s:%d: %w", loginHost, port, err)
	}

	type callback struct {
		code, state, failure string
	}
	results := make(chan callback, 1)

	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			got := callback{code: query.Get("code"), state: query.Get("state"), failure: query.Get("error")}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			// Nothing the IdP sent is interpolated: `error` is
			// attacker-influencable and this page is served from localhost.
			if got.code != "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<h1>Signed in</h1><p>You can close this window.</p>"))
			} else {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("<h1>Sign-in failed</h1><p>Check the terminal for details.</p>"))
			}
			select {
			case results <- got:
			default:
			}
		}),
	}
	defer server.Close() //nolint:errcheck
	go func() { _ = server.Serve(listener) }()

	if err := open(request.URL); err != nil {
		fmt.Printf("Open this URL to sign in:\n  %s\n", request.URL)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var got callback
	select {
	case got = <-results:
	case <-ctx.Done():
		return nil, fmt.Errorf("login: no redirect within %s", timeout)
	}

	if got.code == "" {
		if got.failure == "" {
			got.failure = "no code returned"
		}
		return nil, fmt.Errorf("login: sign-in failed: %s", got.failure)
	}
	// What stops a different login's code being swapped in.
	if got.state != request.State {
		return nil, fmt.Errorf("login: state mismatch: the redirect did not belong to this login")
	}

	return CompleteAuthorizationCode(ctx, got.code, request, clientID, redirectURI, issuer, nil)
}

// openBrowser shells out rather than taking a dependency for three lines.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
