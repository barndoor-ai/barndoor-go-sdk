# Release Process

This document is for maintainers and describes how to create and publish releases of the Barndoor Go SDK.

## Overview

Go modules are published by pushing a git tag. There is no package registry upload step — consumers fetch the module directly from the git repository via the Go module proxy.

This project uses:
- **Git tags** (`vX.Y.Z`) for versioning
- **Release branches** (`release/X.Y.x`) to allow patch releases without bringing in unreleased changes from `main`
- **GitHub Releases** to document changes and trigger CI verification

## Version Strategy

This SDK is generated. The version is decided in `barndoor-ai/bdai-platform` by
`sdk/VERSION`, which `make check-api-version` holds to what actually changed in
the public OpenAPI spec — oasdiff classifies the diff and refuses a number lower
than it requires:

- **Major** (X.0.0): a breaking API change — an operation removed, an enum
  narrowed, a field made required
- **Minor** (0.X.0): an additive API change — a new operation, a new optional
  field
- **Patch** (0.0.X): an SDK-only change — a fix in the hand-written half, a
  dependency bump, a generator upgrade

So the tag you cut here follows the delivered code rather than being chosen.
`release.yml` verifies it: the tag must match the version in the generated
client's User-Agent (`api/configuration.go`), and for v2+ the module path must
end in `/vN`.

### v2 and the module path

From v2 on, Go requires the major version in the module path — this module is
`github.com/barndoor-ai/barndoor-go-sdk/v2`. A `v2.x.x` tag on a path without
`/v2` is served to nobody, which is why `release.yml` checks it.

## Prereleases: there are none, and none are needed

The other Barndoor SDKs publish a prerelease on every regeneration — npm's `dev`
dist-tag, PyPI's `.devN`. **Go does not, deliberately.**

The module proxy already provides it. Any commit on `main` is installable with
no tag and no workflow:

```bash
go get github.com/barndoor-ai/barndoor-go-sdk/v2@main
```

The proxy synthesises a pseudo-version from the commit
(`v2.2.1-0.20260925181123-0f875595d629`), which sorts below any real release and
is ignored by `go get -u` and by minimal version selection unless asked for by
name — exactly the semantics a `dev` channel has elsewhere.

Tagging prereleases instead would be strictly worse. **The proxy caches a tag
immutably**: it cannot be moved, deleted or replaced, only superseded. A tag per
regeneration would mean dozens of permanent, uncleanable tags a week, for a
version nobody resolves by default.

So: tag formal releases only.

---

## Creating a New Release

### 1. Major or Minor Release (from `main`)

Use this process when releasing a new major or minor version (e.g., `1.0.0` or `1.1.0`).

#### Step 1: Prepare the release branch

```bash
# Ensure you're up to date
git checkout main
git pull origin main

# Create a new release branch for this minor version
git checkout -b release/1.2.x
git push origin release/1.2.x
```

#### Step 2: Confirm the version, do not set it

There is nothing to edit. The version is already in the tree, delivered from
`bdai-platform` along with the client, and the release must match it:

```bash
grep -oE 'OpenAPI-Generator/[^/]+/go' api/configuration.go
```

If that reports a different number from the release you intend to cut, tag the
commit whose delivery carried the one you want — do not edit the file, because
the next regeneration push overwrites it. `release.yml` fails the release on a
mismatch.

#### Step 3: Verify locally

```bash
go build ./...
go vet ./...
go test -race ./...
```

#### Step 4: Create and push the version tag

```bash
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```

#### Step 5: Create a GitHub Release

Go to [GitHub Releases](../../releases) and create a new release:

1. Click **"Draft a new release"**
2. **Tag**: Select `v1.2.0` (the tag you just pushed)
3. **Target**: Select the `release/1.2.x` branch
4. **Title**: `v1.2.0`
5. **Description**: Add release notes (features, fixes, breaking changes)
6. **Set as latest release**: Check this for major/minor releases
7. Click **"Publish release"**

This triggers the release workflow which verifies the build and tests pass on Go 1.22 and 1.23.

#### Step 6: Verify the release

Check that:
- The [Release workflow](../../actions/workflows/release.yml) completed successfully
- The module is available: `go get github.com/barndoor-ai/barndoor-go-sdk/v2@v2.2.0`
- The Go module proxy has indexed it: `https://pkg.go.dev/github.com/barndoor-ai/barndoor-go-sdk/v2@v2.2.0`

> **Note:** The release branch (`release/1.2.x`) remains available for future patch releases. You do not need to merge it back to `main` unless you make changes on the release branch that should be backported.

---

### 2. Patch Release (from existing release branch)

Use this process when creating a patch release (e.g., `1.2.1`) to fix bugs in an already-released minor version.

#### Step 1: Create a feature branch from the release branch

```bash
git checkout release/1.2.x
git pull origin release/1.2.x

git checkout -b fix/critical-bug-in-1.2
```

#### Step 2: Make your changes and commit

```bash
# Make your bug fix changes, then:
git add .
git commit -m "fix: resolve critical bug in authentication"
```

#### Step 3: Create a PR targeting the release branch

```bash
git push origin fix/critical-bug-in-1.2
```

Open a pull request on GitHub:
- **Base branch**: `release/1.2.x` (not `main`)
- **Compare branch**: `fix/critical-bug-in-1.2`

Review and merge the PR.

#### Step 4: Bump version and tag the patch release

After merging the fix PR:

```bash
git checkout release/1.2.x
git pull origin release/1.2.x
```

Confirm the delivered version matches the patch you intend to tag (see Step 2
above — there is no constant to edit), then:

```bash
git commit -m "chore: bump version to v1.2.1"
git push origin release/1.2.x

git tag -a v1.2.1 -m "Release v1.2.1"
git push origin v1.2.1
```

#### Step 5: Create a GitHub Release

Follow the same GitHub Release process as Step 5 in the major/minor release, using tag `v1.2.1`.

#### Step 6: Backport to main (if needed)

Decide whether this fix should also be in `main`:

**Option A: Cherry-pick specific commits**

```bash
git checkout main
git pull origin main
git checkout -b backport/critical-bug-fix
git cherry-pick <commit-hash-from-release-branch>
git push origin backport/critical-bug-fix
```

Open a PR targeting `main`.

**Option B: Merge the release branch**

Open a PR from `release/1.2.x` into `main` with title "Backport v1.2.1 fixes to main".

**Option C: No backport needed**

If the issue only affects the released version or has already been fixed differently in `main`, skip this step.

---

## Pre-release Checklist

Before creating a release, ensure:

- [ ] All CI checks pass on the release branch
- [ ] Tests pass locally: `go test -race ./...`
- [ ] Linting passes: `go vet ./...`
- [ ] `go mod tidy` produces no changes
- [ ] `api/configuration.go`'s User-Agent version matches the tag you're about to create
- [ ] Release notes are prepared
- [ ] Breaking changes are clearly documented (for major releases)

## Retraction

If a critical issue is discovered after release, you can retract the version by adding a `retract` directive to `go.mod`:

```go
retract v1.2.0 // Critical bug in authentication
```

Then publish a patch release with the fix and the retraction.
