# Contributing

**This repository is generated. Changes made here are overwritten.**

Both halves of the SDK are built in [`barndoor-ai/bdai-platform`][monorepo] under
`sdk/go/` and pushed here by its `Publish SDKs` workflow:

- `api/` is generated from the OpenAPI document that ships beside it as
  `openapi.yaml`. It is not edited by hand in either repository.
- the hand-written half — `client.go`, `auth.go`, `http.go`, `config.go`,
  `mcp.go`, `cli.go`, `bdtime/`, `cmd/` — lives at `sdk/go/` in the monorepo.
- `README.md`, `examples/` and the tests come from there too.

So a fix belongs in `sdk/go/` in the monorepo, where CI regenerates the client,
builds it and runs the tests before anything reaches this repository. A change
made here survives until the next push and then disappears without warning.

## What this repository owns

`.github/` — CI and the release workflow. The push deliberately carries no
`workflows` permission, so it cannot touch them.

Everything else is delivered.

## Releasing

Tags are cut here; see [RELEASE.md](RELEASE.md). Two things about Go that differ
from the other Barndoor SDKs:

- there is no registry. The module proxy serves this module straight from a git
  tag, so a tag **is** the release and there is no prerelease channel.
- the proxy caches a tag immutably. A bad tag cannot be moved or deleted, only
  superseded by a higher one.

[monorepo]: https://github.com/barndoor-ai/bdai-platform
