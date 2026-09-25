package barndoor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// A Keycloak-shaped stand-in that records what its token endpoint was sent.
type idp struct {
	*httptest.Server

	tokenRequests []url.Values
	accessTokens  []string
	expiresIn     int
	refreshToken  string
	tokenStatus   int
	discoveryBody string
}

func newIDP(t *testing.T, accessTokens ...string) *idp {
	t.Helper()
	i := &idp{accessTokens: accessTokens, tokenStatus: http.StatusOK}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if i.discoveryBody != "" {
			_, _ = w.Write([]byte(i.discoveryBody))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         i.URL,
			"token_endpoint": i.URL + "/protocol/openid-connect/token",
		})
	})
	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		i.tokenRequests = append(i.tokenRequests, r.Form)

		if i.tokenStatus != http.StatusOK {
			w.WriteHeader(i.tokenStatus)
			return
		}
		token := "access-0"
		if n := len(i.tokenRequests) - 1; n < len(i.accessTokens) {
			token = i.accessTokens[n]
		} else if len(i.accessTokens) > 0 {
			token = i.accessTokens[len(i.accessTokens)-1]
		}
		body := map[string]any{"access_token": token, "token_type": "Bearer"}
		if i.expiresIn != 0 {
			body["expires_in"] = i.expiresIn
		}
		if i.refreshToken != "" {
			body["refresh_token"] = i.refreshToken
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	i.Server = httptest.NewServer(mux)
	t.Cleanup(i.Close)
	return i
}

func TestStaticToken(t *testing.T) {
	tok, err := StaticToken("bdai_key").Token()
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "bdai_key" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	// An API key arriving with the wrong scheme is a 401 nobody can read.
	if tok.Type() != "Bearer" {
		t.Errorf("Type() = %q, want Bearer", tok.Type())
	}
	if !tok.Valid() {
		t.Error("a static token must never look expired")
	}
}

func TestDiscoverTokenEndpoint(t *testing.T) {
	server := newIDP(t)
	got, err := DiscoverTokenEndpoint(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := server.URL + "/protocol/openid-connect/token"; got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

func TestDiscoverTokenEndpointTrimsATrailingSlash(t *testing.T) {
	server := newIDP(t)
	if _, err := DiscoverTokenEndpoint(context.Background(), server.URL+"/", nil); err != nil {
		t.Fatalf("a trailing slash on the issuer must not produce a double slash: %v", err)
	}
}

func TestDiscoverTokenEndpointErrors(t *testing.T) {
	t.Run("non-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		if _, err := DiscoverTokenEndpoint(context.Background(), server.URL, nil); err == nil {
			t.Error("want an error for HTTP 404")
		}
	})

	t.Run("no token_endpoint", func(t *testing.T) {
		server := newIDP(t)
		server.discoveryBody = `{"issuer":"x"}`
		_, err := DiscoverTokenEndpoint(context.Background(), server.URL, nil)
		if err == nil || !strings.Contains(err.Error(), "token_endpoint") {
			t.Errorf("err = %v, want one naming token_endpoint", err)
		}
	})
}

// Constructing a source must perform no I/O.
func TestClientCredentialsIsLazy(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_ = ClientCredentials(context.Background(), ClientCredentialsOptions{
		ClientID: "id", ClientSecret: "secret", Issuer: server.URL,
	})
	if got := calls.Load(); got != 0 {
		t.Errorf("made %d requests while constructing the source, want 0", got)
	}
}

func TestClientCredentialsExchangesAndCaches(t *testing.T) {
	server := newIDP(t, "access-0")
	server.expiresIn = 3600

	src := ClientCredentials(context.Background(), ClientCredentialsOptions{
		ClientID: "id", ClientSecret: "secret", Issuer: server.URL, Scopes: []string{"openid"},
	})

	for i := range 3 {
		tok, err := src.Token()
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if tok.AccessToken != "access-0" {
			t.Errorf("call %d: AccessToken = %q", i, tok.AccessToken)
		}
	}

	if len(server.tokenRequests) != 1 {
		t.Fatalf("token endpoint hit %d times, want 1 — the source is not caching", len(server.tokenRequests))
	}
	form := server.tokenRequests[0]
	if form.Get("grant_type") != "client_credentials" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("scope") != "openid" {
		t.Errorf("scope = %q", form.Get("scope"))
	}
}

// Caching the failure would kill a client over one DNS blip at startup.
func TestAFailedExchangeIsNotCached(t *testing.T) {
	server := newIDP(t, "access-0")
	server.tokenStatus = http.StatusInternalServerError

	src := ClientCredentials(context.Background(), ClientCredentialsOptions{
		ClientID: "id", ClientSecret: "secret", Issuer: server.URL,
	})
	if _, err := src.Token(); err == nil {
		t.Fatal("want an error from a failing token endpoint")
	}

	server.tokenStatus = http.StatusOK
	tok, err := src.Token()
	if err != nil {
		t.Fatalf("the source did not recover: %v", err)
	}
	if tok.AccessToken != "access-0" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
}

// Covering only discovery would send credentials to the real IdP — a test that
// passes while talking to production.
func TestClientCredentialsUsesTheInjectedClientForBothLegs(t *testing.T) {
	server := newIDP(t, "access-0")

	var seen atomic.Int32
	hc := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		seen.Add(1)
		return http.DefaultTransport.RoundTrip(req)
	})}

	src := ClientCredentials(context.Background(), ClientCredentialsOptions{
		ClientID: "id", ClientSecret: "secret", Issuer: server.URL, HTTPClient: hc,
	})
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}
	if got := seen.Load(); got != 2 {
		t.Errorf("the injected client saw %d requests, want 2 (discovery and the exchange)", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRefreshTokenExchangesTheRefreshGrant(t *testing.T) {
	server := newIDP(t, "access-0")
	server.expiresIn = 3600

	src := RefreshToken(context.Background(), "refresh-0", "cli", server.URL, nil)
	tok, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-0" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if len(server.tokenRequests) != 1 {
		t.Fatalf("token endpoint hit %d times, want 1", len(server.tokenRequests))
	}
	form := server.tokenRequests[0]
	if form.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("refresh_token") != "refresh-0" {
		t.Errorf("refresh_token = %q", form.Get("refresh_token"))
	}
}

// A source that kept sending the original would work exactly once.
func TestRefreshTokenFollowsRotation(t *testing.T) {
	server := newIDP(t, "access-0", "access-1")
	server.refreshToken = "refresh-1"
	// Expired on arrival, so the second call must exchange again.
	server.expiresIn = -1

	src := RefreshToken(context.Background(), "refresh-0", "cli", server.URL, nil)
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Token(); err != nil {
		t.Fatal(err)
	}

	if len(server.tokenRequests) != 2 {
		t.Fatalf("token endpoint hit %d times, want 2", len(server.tokenRequests))
	}
	if got := server.tokenRequests[1].Get("refresh_token"); got != "refresh-1" {
		t.Errorf("second exchange sent refresh_token %q, want the rotated refresh-1", got)
	}
}

func TestStartAuthorizationCodeBuildsAPKCEChallenge(t *testing.T) {
	req, err := StartAuthorizationCode("cli", "http://127.0.0.1:52765/cb", "https://issuer.test/realms/r", nil)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://issuer.test/realms/r/protocol/openid-connect/auth"; parsed.Scheme+"://"+parsed.Host+parsed.Path != want {
		t.Errorf("authorization endpoint = %q, want %q", parsed.Scheme+"://"+parsed.Host+parsed.Path, want)
	}

	q := parsed.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("state") != req.State {
		t.Errorf("state in the URL = %q, returned %q", q.Get("state"), req.State)
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("scope") != "openid profile email offline_access" {
		t.Errorf("scope = %q", q.Get("scope"))
	}

	// A mismatch is a login that fails only against a real IdP.
	sum := sha256.Sum256([]byte(req.Verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); q.Get("code_challenge") != want {
		t.Errorf("code_challenge = %q, want S256 of the verifier", q.Get("code_challenge"))
	}
}

// A constant state would let any redirect complete any pending login.
func TestStartAuthorizationCodeStateAndVerifierAreFresh(t *testing.T) {
	first, err := StartAuthorizationCode("cli", "http://127.0.0.1/cb", "https://issuer.test/realms/r", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := StartAuthorizationCode("cli", "http://127.0.0.1/cb", "https://issuer.test/realms/r", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.State == second.State {
		t.Error("two logins share a state")
	}
	if first.Verifier == second.Verifier {
		t.Error("two logins share a PKCE verifier")
	}
}

func TestStartAuthorizationCodeDefaultsToProduction(t *testing.T) {
	req, err := StartAuthorizationCode("cli", "http://127.0.0.1/cb", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req.URL, ProductionIssuer+"/protocol/openid-connect/auth") {
		t.Errorf("URL = %q, want it rooted at ProductionIssuer", req.URL)
	}
}

func TestCompleteAuthorizationCodeSendsTheVerifier(t *testing.T) {
	server := newIDP(t, "access-0")
	server.refreshToken = "refresh-0"

	req := AuthorizationCodeRequest{State: "state", Verifier: "verifier-value"}
	tok, err := CompleteAuthorizationCode(context.Background(), "the-code", req, "cli", "http://127.0.0.1/cb", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "refresh-0" {
		t.Errorf("RefreshToken = %q — a caller cannot persist a session without it", tok.RefreshToken)
	}

	form := server.tokenRequests[0]
	if form.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("code") != "the-code" {
		t.Errorf("code = %q", form.Get("code"))
	}
	if form.Get("code_verifier") != "verifier-value" {
		t.Errorf("code_verifier = %q, want the verifier from the request", form.Get("code_verifier"))
	}
}
