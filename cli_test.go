package barndoor

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// freePort picks a port the loopback server can bind. LoginInteractive builds
// the redirect URI from the number, so it cannot use :0.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

// browser stands in for the user: it follows the authorization URL and calls
// the redirect back, as a real IdP would.
func browser(t *testing.T, transform func(q url.Values)) func(string) error {
	t.Helper()
	return func(authURL string) error {
		parsed, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		q := url.Values{"code": {"the-code"}, "state": {parsed.Query().Get("state")}}
		if transform != nil {
			transform(q)
		}
		redirect, err := url.Parse(parsed.Query().Get("redirect_uri"))
		if err != nil {
			return err
		}
		redirect.RawQuery = q.Encode()

		go func() {
			resp, err := http.Get(redirect.String())
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
}

func TestLoginInteractive(t *testing.T) {
	server := newIDP(t, "access-0")
	server.refreshToken = "refresh-0"

	token, err := LoginInteractive(context.Background(), LoginOptions{
		Port:        freePort(t),
		Issuer:      server.URL,
		Timeout:     10 * time.Second,
		OpenBrowser: browser(t, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access-0" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
	if token.RefreshToken != "refresh-0" {
		t.Errorf("RefreshToken = %q — a caller cannot persist a session without it", token.RefreshToken)
	}

	form := server.tokenRequests[0]
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "the-code" {
		t.Errorf("exchange sent %v", form)
	}
	if form.Get("code_verifier") == "" {
		t.Error("the exchange carried no PKCE verifier")
	}
}

// The state check is what stops a different login's code being swapped in.
func TestLoginInteractiveRejectsAStateMismatch(t *testing.T) {
	server := newIDP(t, "access-0")

	_, err := LoginInteractive(context.Background(), LoginOptions{
		Port:    freePort(t),
		Issuer:  server.URL,
		Timeout: 10 * time.Second,
		OpenBrowser: browser(t, func(q url.Values) {
			q.Set("state", "someone-elses-login")
		}),
	})
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("err = %v, want a state mismatch", err)
	}
	if len(server.tokenRequests) != 0 {
		t.Error("exchanged a code whose state did not match")
	}
}

func TestLoginInteractiveSurfacesAnIdpError(t *testing.T) {
	server := newIDP(t, "access-0")

	_, err := LoginInteractive(context.Background(), LoginOptions{
		Port:    freePort(t),
		Issuer:  server.URL,
		Timeout: 10 * time.Second,
		OpenBrowser: browser(t, func(q url.Values) {
			q.Del("code")
			q.Set("error", "access_denied")
		}),
	})
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("err = %v, want the IdP's error surfaced", err)
	}
}

func TestLoginInteractiveTimesOut(t *testing.T) {
	server := newIDP(t, "access-0")

	start := time.Now()
	_, err := LoginInteractive(context.Background(), LoginOptions{
		Port:        freePort(t),
		Issuer:      server.URL,
		Timeout:     200 * time.Millisecond,
		OpenBrowser: func(string) error { return nil }, // nobody ever comes back
	})
	if err == nil || !strings.Contains(err.Error(), "no redirect") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("waited %v", elapsed)
	}
}

// Binding is what makes the flow work, so a port already in use must fail
// before the browser opens rather than hanging.
func TestLoginInteractiveFailsOnABusyPort(t *testing.T) {
	port := freePort(t)
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("could not hold the port: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	opened := false
	_, err = LoginInteractive(context.Background(), LoginOptions{
		Port:        port,
		Issuer:      "https://issuer.test/realms/r",
		Timeout:     2 * time.Second,
		OpenBrowser: func(string) error { opened = true; return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "cannot listen") {
		t.Fatalf("err = %v, want a bind failure", err)
	}
	if opened {
		t.Error("opened a browser for a login that could never complete")
	}
}
