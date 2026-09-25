package barndoor

import (
	"net/http"

	"golang.org/x/oauth2"

	"github.com/barndoor-ai/barndoor-go-sdk/v2/api"
)

// Auth is a RoundTripper, not a per-call context value: the generated client
// takes a TokenSource via api.ContextOAuth2, but that burdens every call site
// and one forgotten call is an unauthenticated request.

// Client is one namespace per service, plus the pieces they share.
type Client struct {
	Registry         *api.RegistryAPIService
	Policy           *api.PolicyAPIService
	Identity         *api.IdentityAPIService
	Notification     *api.NotificationAPIService
	Dlp              *api.DlpAPIService
	LlmGateway       *api.LlmGatewayAPIService
	SystemManagement *api.SystemManagementAPIService

	// Configuration and API reach the generated objects directly.
	Configuration *api.Configuration
	API           *api.APIClient

	// tokenSource is borrowed by the MCP client, so one login serves both
	// protocols and a refresh is shared.
	tokenSource oauth2.TokenSource
}

type options struct {
	env        *Environment
	retry      RetryOptions
	headers    map[string]string
	httpClient *http.Client
	base       http.RoundTripper
}

// An Option configures New.
type Option func(*options)

// WithEnvironment points the client at a non-production deployment.
func WithEnvironment(env Environment) Option {
	return func(o *options) { o.env = &env }
}

// WithRetry replaces the retry policy. RetryOptions{} disables retrying
// entirely.
func WithRetry(r RetryOptions) Option {
	return func(o *options) { o.retry = r }
}

// WithHeader adds a default header to every request.
func WithHeader(name, value string) Option {
	return func(o *options) {
		if o.headers == nil {
			o.headers = map[string]string{}
		}
		o.headers[name] = value
	}
}

// WithHTTPClient replaces the whole client, retries included. The token source
// is still applied on top of its transport.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.httpClient = c }
}

// WithBaseTransport puts a transport underneath the retrying.
func WithBaseTransport(rt http.RoundTripper) Option {
	return func(o *options) { o.base = rt }
}

// New assembles a client. Nothing here touches the network — discovery and the
// first token exchange wait for the first request. Retries are on unless
// switched off with WithRetry(RetryOptions{}).
//
// For an API key or a token you already hold, pass StaticToken(key).
func New(src oauth2.TokenSource, opts ...Option) *Client {
	o := options{retry: DefaultRetryOptions()}
	for _, apply := range opts {
		apply(&o)
	}

	cfg := api.NewConfiguration()
	if o.env != nil {
		// The spec declares one templated server, https://{host}. Replacing
		// the list keeps BaseURL a full URL, which is what a caller pastes.
		cfg.Servers = api.ServerConfigurations{{URL: o.env.BaseURL}}
	}
	for name, value := range o.headers {
		cfg.AddDefaultHeader(name, value)
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = NewHTTPClient(o.retry, o.base)
	}

	// Auth outside retrying: one token per request, reused across its attempts.
	cfg.HTTPClient = &http.Client{
		Transport: &oauth2.Transport{Source: src, Base: httpClient.Transport},
		Timeout:   httpClient.Timeout,
		Jar:       httpClient.Jar,
	}

	client := api.NewAPIClient(cfg)
	return &Client{
		Registry:         client.RegistryAPI,
		Policy:           client.PolicyAPI,
		Identity:         client.IdentityAPI,
		Notification:     client.NotificationAPI,
		Dlp:              client.DlpAPI,
		LlmGateway:       client.LlmGatewayAPI,
		SystemManagement: client.SystemManagementAPI,
		Configuration:    cfg,
		API:              client,
		tokenSource:      src,
	}
}
