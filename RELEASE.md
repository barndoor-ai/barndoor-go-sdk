# Release Process

This document is for maintainers and describes how to create and publish releases of the Barndoor Go SDK.

## Overview

Go modules are published by pushing a git tag. There is no package registry upload step — consumers fetch the module directly from the git repository via the Go module proxy.

This project uses:
- **Git tags** (`vX.Y.Z`) for versioning
- **Release branches** (`release/X.Y.x`) to allow patch releases without bringing in unreleased changes from `main`
- **GitHub Releases** to document changes and trigger CI verification

## Version Strategy

We follow [Semantic Versioning](https://semver.org/):
- **Major** (X.0.0): Breaking changes to the public API
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible

The version constant in `barndoor.go` must match the git tag.

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

#### Step 2: Update the version constant

Edit `barndoor.go` and update the `Version` constant:

```go
const Version = "1.2.0"
```

Commit the change:

```bash
git add barndoor.go
git commit -m "chore: bump version to v1.2.0"
git push origin release/1.2.x
```

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
- The module is available: `go get github.com/barndoor-ai/barndoor-go-sdk@v1.2.0`
- The Go module proxy has indexed it: `https://pkg.go.dev/github.com/barndoor-ai/barndoor-go-sdk@v1.2.0`

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

Update the `Version` constant in `barndoor.go` to `"1.2.1"`, then:

```bash
git add barndoor.go
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
- [ ] `Version` constant in `barndoor.go` matches the tag you're about to create
- [ ] Release notes are prepared
- [ ] Breaking changes are clearly documented (for major releases)

## Retraction

If a critical issue is discovered after release, you can retract the version by adding a `retract` directive to `go.mod`:

```go
retract v1.2.0 // Critical bug in authentication
```

Then publish a patch release with the fix and the retraction.
