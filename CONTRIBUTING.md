# Contributing

This document provides guidelines and instructions for contributing to the Barndoor Go SDK.

## Development Setup

1. Make sure you have Go 1.22+ installed
2. Fork the repository
3. Clone your fork: `git clone https://github.com/YOUR-USERNAME/barndoor-go-sdk.git`
4. Install dependencies:

```bash
go mod download
```

5. Run tests:

```bash
go test ./...
```

6. Verify the build:

```bash
go build ./...
go vet ./...
```
