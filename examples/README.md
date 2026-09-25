# Examples

Runnable against a real Barndoor organization. Each one reads its credentials
from the environment and says which variables it needs.

| File | Shows |
|---|---|
| `list_mcp_servers.go` | The smallest useful call — authenticate and read |
| `machine_to_machine.go` | Client-credentials auth, refreshed for you |
| `mcp_client.go` | Connecting to MCP and listing tools |
| `connection_params.go` | MCP connection details for another framework |

```bash
go get github.com/barndoor-ai/barndoor-go-sdk/v2
BARNDOOR_API_KEY=bdai_… go run examples/list_mcp_servers.go
```

Each is its own `package main` and carries `//go:build ignore` so they can share
a directory — `go run` on a named file ignores the constraint.

These are compiled against the client on every regeneration, so an API change
that breaks one fails CI rather than reaching you.
