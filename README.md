# Barndoor Go SDK

The Go client for the [Barndoor](https://barndoor.ai) public API.

```bash
go get github.com/barndoor-ai/barndoor-go-sdk/v2
```

> **v2 changes the import path.** Go requires the major version in the module
> path from v2 onward, so `github.com/barndoor-ai/barndoor-go-sdk` becomes
> `github.com/barndoor-ai/barndoor-go-sdk/v2`. That is the only source change
> most callers need.

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	barndoor "github.com/barndoor-ai/barndoor-go-sdk/v2"
)

func main() {
	client := barndoor.New(barndoor.StaticToken(os.Getenv("BARNDOOR_API_KEY")))

	page, resp, err := client.Registry.ListMcpServers(context.Background()).Limit(25).Execute()
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	for _, server := range page.Data {
		fmt.Println(server.Id, server.Name)
	}
}
```

Every operation returns `(value, *http.Response, error)`. The response is the
raw one, so its body has to be closed; the value is already deserialised.

## Authentication

`New` takes an `oauth2.TokenSource`, so anything in `golang.org/x/oauth2` works
alongside the three flows here.

| Flow | Use it for |
|---|---|
| `StaticToken(key)` | an API key from the dashboard, or a token you already hold |
| `ClientCredentials(ctx, opts)` | a service authenticating as itself |
| `RefreshToken(ctx, …)` | keeping a user session alive |
| `StartAuthorizationCode` / `CompleteAuthorizationCode` | an interactive login (PKCE) |
| `LoginInteractive` | the same flow, browser and loopback redirect included |

Tokens are fetched lazily and refreshed automatically: constructing a client
performs no I/O, so a briefly unreachable identity provider cannot stop your
process from starting. `ctx` on the token flows governs the source for its whole
life, not one exchange — pass `context.Background()` unless you have a reason
otherwise.

The SDK stores nothing on disk. `CompleteAuthorizationCode` hands back the raw
token so your application decides where a credential belongs.

## Environments

Production needs no configuration. For anything else:

```go
client := barndoor.New(src, barndoor.WithEnvironment(barndoor.DEV))
```

`EnvironmentFromEnv` reads `BARNDOOR_ENV` (`dev` or `local`) and
`BARNDOOR_API_URL`, and returns `ok == false` for production. It is opt-in: the
SDK never reads the environment by itself, because a library that re-points
itself at another cluster because of a stray variable is a bad surprise.

## Retries

On by default: three attempts after the first, exponential backoff with jitter,
`Retry-After` honoured. Only idempotent methods are retried — a 502 does not say
whether a `POST` reached the application, and a silent duplicate write is worse
than a surfaced error.

```go
barndoor.New(src, barndoor.WithRetry(barndoor.RetryOptions{}))          // off
barndoor.New(src, barndoor.WithRetry(barndoor.RetryOptions{Retries: 5, Timeout: time.Minute, Backoff: time.Second}))
```

Retrying lives in an `http.RoundTripper`, so `WithBaseTransport` puts your own
transport underneath it and `WithHTTPClient` replaces the lot. Authentication is
applied on top either way.

## MCP

The platform serves the Model Context Protocol on the same host with your
organization in front of it. `NewMcpClient` opens a session, already through
`initialize`:

```go
session, err := barndoor.NewMcpClient(ctx, client, "acme", "", barndoor.McpOptions{})
defer session.Close()
tools, err := session.ListTools(ctx, nil)
```

Omit the server for the universal endpoint (`/mcp`), which exposes every server
you can reach; pass a slug or id for one server (`/mcp/<slug>`).

`McpConnectionParams` returns the URL and headers without connecting, for
handing to another framework. The headers carry a bearer token — treat them as a
secret. Either way the session borrows the REST client's token source, so one
login serves both protocols and a refresh is shared.

## Interactive login

`LoginInteractive` runs the browser flow against a loopback redirect and returns
the token, refresh token included:

```go
token, err := barndoor.LoginInteractive(ctx, barndoor.LoginOptions{})
```

`go run github.com/barndoor-ai/barndoor-go-sdk/v2/cmd/barndoor-login` does the
same from a terminal. It binds a port, so nothing starts unless you call it.

## Timestamps

Timestamp fields are `bdtime.Time`, not `time.Time`. It embeds `time.Time`, so
`Year()`, `Before()`, `Format()` and the rest work unchanged and `.Time` gets you
the standard value.

It exists because some Barndoor endpoints serialise timestamps without a UTC
offset (`2026-05-08T17:26:31.084181`), which `time.Time` rejects outright —
failing the whole response rather than one field. `bdtime.Time` reads those as
UTC, keeps an explicit offset when one is present, and always *sends* RFC 3339.

## Layout

`package barndoor` at the module root is hand-written — tokens, transport,
environments — as is `bdtime`. Everything under `api/` is generated from the OpenAPI document
shipped beside it as `openapi.yaml`, and `client.API` and `client.Configuration`
reach the generated objects directly when you need an operation the namespaces
do not expose.

## Contributing

**This repository is generated.** Both halves are built in
`barndoor-ai/bdai-platform` under `sdk/go/` and pushed here; an edit made in
this repository is overwritten by the next push. Send changes there.
