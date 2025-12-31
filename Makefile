.PHONY: build test clean lint fmt ci gazelle help

## Build the CLI binary
build:
	bazel build //:zitadel-cli

## Run all tests
test:
	bazel test //...

## Clean build artifacts
clean:
	bazel clean

## Run linter (golangci-lint via Bazel)
lint:
	bazel run //tools:lint

## Format code (gofumpt via Bazel)
fmt:
	bazel run //tools:fmt

## Run all CI checks (fmt, lint, test)
ci: fmt lint test

## Update BUILD files after Go changes
gazelle:
	bazel run //:gazelle

## Show help
help:
	@echo "make build   - Build CLI binary"
	@echo "make test    - Run tests"
	@echo "make lint    - Run linter"
	@echo "make fmt     - Format code"
	@echo "make ci      - Run fmt, lint, and test"
	@echo "make gazelle - Update BUILD files"
	@echo "make clean   - Clean build"
