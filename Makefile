SHELL := /bin/bash
.DEFAULT_GOAL := help

BIN_DIR    := bin
GOEXE      := $(shell go env GOEXE)
BINARY     := $(BIN_DIR)/trove$(GOEXE)
PKG        := github.com/steveokay/trove

COVERAGE_MIN ?= 95.0

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.version=$(VERSION) \
	-X $(PKG)/internal/version.commit=$(COMMIT) \
	-X $(PKG)/internal/version.date=$(BUILD_DATE)

# Linux parity image. Debian-based official Go image: ships git, gcc and make,
# so no custom Dockerfile is needed. See docs/dev/environment.md.
LINUX_IMAGE ?= golang:1.23-bookworm
# Docker Desktop wants a Windows-style path; pwd -W provides it under Git Bash.
HOST_PWD := $(shell pwd -W 2>/dev/null || pwd)

.PHONY: help
help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the trove binary into bin/
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/trove

.PHONY: test
test: ## Run the test suite with the race detector
	go test ./... -race -covermode=atomic -coverpkg=./...

.PHONY: cover
cover: ## Run tests and enforce the coverage gate (>=95%)
	go test ./... -covermode=atomic -coverpkg=./... -coverprofile=coverage.out
	bash scripts/coverage.sh coverage.out $(COVERAGE_MIN)

.PHONY: cover-html
cover-html: cover ## Open the coverage report in a browser
	go tool cover -html=coverage.out

.PHONY: cover-selftest
cover-selftest: ## Verify the coverage gate script itself
	bash scripts/coverage_test.sh

.PHONY: lint
lint: ## Run go vet and golangci-lint
	go vet ./...
	golangci-lint run

.PHONY: fmt
fmt: ## Format all Go source
	gofmt -w cmd internal

.PHONY: test-linux
test-linux: ## Run the full suite in a Linux container (parity with CI)
	MSYS_NO_PATHCONV=1 docker run --rm \
		-v "$(HOST_PWD)":/src \
		-v trove-gocache:/root/.cache/go-build \
		-v trove-gomodcache:/go/pkg/mod \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-w /src $(LINUX_IMAGE) \
		make test

.PHONY: tidy
tidy: ## Tidy and verify module dependencies
	go mod tidy
	go mod verify

.PHONY: vendor-audit
vendor-audit: ## Print the module dependency graph for review
	go list -m all

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -rf $(BIN_DIR) coverage.out
