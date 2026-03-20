GOSEC_VERSION := $(shell cat .gosec-version)
PACKAGES := $(shell go list ./... | grep -v /examples/)

.PHONY: all build test test-race coverage lint vet security tidy verify download clean check install-hooks install-tools

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
	go test $(PACKAGES)

test-race:
	go test -race $(PACKAGES)

coverage:
	go test -race -coverprofile=coverage.out $(PACKAGES)
	go tool cover -func=coverage.out

## Static analysis
vet:
	go vet $(PACKAGES)

lint: vet

security:
	gosec $(PACKAGES)

## Pre-commit / CI check
check: vet security test-race

## Tools
install-tools:
	go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

## Git hooks
install-hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

## Cleanup
clean:
	rm -f coverage.out
