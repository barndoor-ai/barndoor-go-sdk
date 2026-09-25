package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Getting a token — the half of auth no OpenAPI document describes. Every flow
// returns an oauth2.TokenSource, which is what the generated client already
// understands, and x/oauth2 does the caching, locking and refresh.

// expirySkew stops a token being handed out shortly before it expires, so one
// cannot die in flight. oauth2's own default is 10s.
const expirySkew = 60 * time.Second

// StaticToken is a token you already hold — an API key, or one sourced
// elsewhere. It never expires and is never refreshed.
func StaticToken(token string) oauth2.TokenSource {
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token, TokenType: "Bearer"})
}

// ClientCredentialsOptions are machine-to-machine credentials, exchanged and
// refreshed for you.
type ClientCredentialsOptions struct {
	ClientID     string
	ClientSecret string
	// Issuer defaults to ProductionIssuer.
	Issuer string
	// Scopes defaults to what every published operation requires.
	Scopes []string
	// HTTPClient covers both discovery and the token exchange.
	HTTPClient *http.Client
}

// ClientCredentials exchanges client credentials for access tokens, refreshing
// as needed. Nothing here touches the network until the first Token call.
//
// ctx governs the source for its whole life, not one exchange — cancelling it
// stops future refreshes.
func ClientCredentials(ctx context.Context, opts ClientCredentialsOptions) oauth2.TokenSource {
	ctx = withHTTPClient(ctx, opts.HTTPClient)
	issuer := orProduction(opts.Issuer)

	return lazy(ctx, func(ctx context.Context) (oauth2.TokenSource, error) {
		endpoint, err := DiscoverTokenEndpoint(ctx, issuer, opts.HTTPClient)
		if err != nil {
			return nil, err
		}
		cfg := clientcredentials.Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			TokenURL:     endpoint,
			Scopes:       opts.Scopes,
		}
		return cfg.TokenSource(ctx), nil
	})
}

// RefreshToken keeps a user session alive from a refresh token.
//
// Keycloak rotates refresh tokens by default. oauth2 follows the rotation, but
// the token passed in here is spent after the first exchange — do not build a
// second source from it.
func RefreshToken(ctx context.Context, token string, clientID string, issuer string, hc *http.Client) oauth2.TokenSource {
	ctx = withHTTPClient(ctx, hc)
	resolved := orProduction(issuer)

	return lazy(ctx, func(ctx context.Context) (oauth2.TokenSource, error) {
		endpoint, err := DiscoverTokenEndpoint(ctx, resolved, hc)
		if err != nil {
			return nil, err
		}
		cfg := oauth2.Config{
			ClientID: clientID,
			Endpoint: oauth2.Endpoint{TokenURL: endpoint},
		}
		// An empty AccessToken is invalid, so the first Token call exchanges.
		return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: token}), nil
	})
}

// AuthorizationCodeRequest is where to send the user, and what to hold until
// the redirect arrives. State and Verifier must not be shared between
// concurrent logins.
type AuthorizationCodeRequest struct {
	URL      string
	State    string
	Verifier string
}

// StartAuthorizationCode begins an interactive login. PKCE always, even for
// confidential clients. Touches no network, so a caller can render a link
// without a context. scopes may be nil.
func StartAuthorizationCode(clientID, redirectURI, issuer string, scopes []string) (AuthorizationCodeRequest, error) {
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	state, err := randomState()
	if err != nil {
		return AuthorizationCodeRequest{}, err
	}
	verifier := oauth2.GenerateVerifier()

	cfg := oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL: strings.TrimRight(orProduction(issuer), "/") + "/protocol/openid-connect/auth",
		},
	}
	return AuthorizationCodeRequest{
		URL:      cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)),
		State:    state,
		Verifier: verifier,
	}, nil
}

// CompleteAuthorizationCode exchanges the code for tokens and returns them raw,
// so the caller decides where to persist RefreshToken. The SDK stores nothing.
//
// Check req.State against the redirect's state BEFORE calling this — only the
// caller knows which pending login a redirect belongs to.
func CompleteAuthorizationCode(ctx context.Context, code string, req AuthorizationCodeRequest, clientID, redirectURI, issuer string, hc *http.Client) (*oauth2.Token, error) {
	ctx = withHTTPClient(ctx, hc)
	endpoint, err := DiscoverTokenEndpoint(ctx, orProduction(issuer), hc)
	if err != nil {
		return nil, err
	}
	cfg := oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Endpoint:    oauth2.Endpoint{TokenURL: endpoint},
	}
	return cfg.Exchange(ctx, code, oauth2.VerifierOption(req.Verifier))
}

// DiscoverTokenEndpoint resolves the token endpoint from the issuer's discovery
// document, rather than assembling a path an issuer is free to move.
func DiscoverTokenEndpoint(ctx context.Context, issuer string, hc *http.Client) (string, error) {
	wellKnown := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", err
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("openid discovery at %s: %w", wellKnown, err)
	}
	defer resp.Body.Close() //nolint:errcheck // a read-only body

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openid discovery at %s: HTTP %d", wellKnown, resp.StatusCode)
	}

	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("openid discovery at %s: %w", wellKnown, err)
	}
	if doc.TokenEndpoint == "" {
		return "", fmt.Errorf("%s declares no token_endpoint", wellKnown)
	}
	return doc.TokenEndpoint, nil
}

func orProduction(issuer string) string {
	if issuer == "" {
		return ProductionIssuer
	}
	return issuer
}

// withHTTPClient puts the caller's client where oauth2 looks for it, so the
// exchange and discovery share a transport.
func withHTTPClient(ctx context.Context, hc *http.Client) context.Context {
	if hc == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, hc)
}

// lazySource defers building the real source to the first Token call, so
// constructing a client performs no I/O. A failed build is not cached — one DNS
// blip at startup must not kill the client permanently.
type lazySource struct {
	ctx   context.Context
	build func(context.Context) (oauth2.TokenSource, error)

	mu  sync.Mutex
	src oauth2.TokenSource
}

func lazy(ctx context.Context, build func(context.Context) (oauth2.TokenSource, error)) oauth2.TokenSource {
	// The WithExpiry variant is what applies expirySkew.
	return oauth2.ReuseTokenSourceWithExpiry(nil, &lazySource{ctx: ctx, build: build}, expirySkew)
}

func (l *lazySource) Token() (*oauth2.Token, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.src == nil {
		src, err := l.build(l.ctx)
		if err != nil {
			return nil, err
		}
		l.src = src
	}
	return l.src.Token()
}
