.PHONY: all build test test-race coverage lint vet security tidy verify download clean check install-hooks

all: check

## Dependencies
download:
	go mod download

tidy:
	go mod tidy

verify:
	go mod verify

## Build
build:
	go build ./...

## Testing
test:
	go test ./...

test-race:
	go test -race ./...

coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

## Static analysis
vet:
	go vet ./...

lint: vet

security:
	gosec ./...

## Pre-commit / CI check
check: vet security test-race

## Git hooks
install-hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

## Cleanup
clean:
	rm -f coverage.out
