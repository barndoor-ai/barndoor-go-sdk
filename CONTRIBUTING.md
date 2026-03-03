# Contributing

This document provides guidelines and instructions for contributing to the Barndoor Go SDK.

## Development Setup

1. Make sure you have Go 1.22+ installed
2. Fork the repository
3. Clone your fork: `git clone https://github.com/YOUR-USERNAME/barndoor-go-sdk.git`
4. Install dependencies and the pre-commit hook:

```bash
make download
make install-hooks
```

The pre-commit hook runs `make check` (vet, security scan, and race-detected tests) before every commit.

5. Run tests:

```bash
make test
```

6. Run the full check suite (vet + gosec + tests with `-race`):

```bash
make check
```
