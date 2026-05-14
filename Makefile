SHELL := /bin/bash

BIN_DIR    := .bin
BIN        := $(BIN_DIR)/tempogate
PKG        := github.com/fenmoai/tempogate
BUILDINFO  := $(PKG)/buildinfo

GIT_TAG    ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0-dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X '$(BUILDINFO).version=$(VERSION)' \
	-X '$(BUILDINFO).gitTag=$(GIT_TAG)' \
	-X '$(BUILDINFO).gitCommit=$(GIT_COMMIT)' \
	-X '$(BUILDINFO).buildDate=$(BUILD_DATE)'

.PHONY: start build fmt vet lint imports check tidy test ci gen-oas clean help

start: ## Run the binary directly with build-info ldflags injected
	go run -ldflags "$(LDFLAGS)" .

build: ## Build distroless-bound binary into $(BIN_DIR)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

fmt: ## go fmt + goimports-equivalent ordering (see imports target)
	go fmt ./...

vet: ## go vet ./...
	go vet ./...

lint: ## golangci-lint run
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not installed: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	}
	golangci-lint run ./...

imports: ## gci write with std/default/local groupings
	@command -v gci >/dev/null 2>&1 || { \
		echo "gci not installed: go install github.com/daixiang0/gci@latest"; \
		exit 1; \
	}
	gci write --skip-generated -s standard -s default -s "prefix($(PKG))" .

check: fmt vet imports ## fmt + vet + imports; fails if git diff is non-empty
	@if ! git diff --quiet --exit-code; then \
		echo "check: working tree dirty after fmt/vet/imports"; \
		git --no-pager diff --stat; \
		exit 1; \
	fi

tidy: ## go mod tidy
	go mod tidy

test: check ## check + race + coverage
	go test -race -covermode=atomic -coverprofile=coverage.out ./...

ci: test ## test + future cov/xml hooks
	go tool cover -func=coverage.out | tail -1

gen-oas: build ## emit OpenAPI spec (subcommand lands with E1.3)
	$(BIN) gen-oas -f yaml > api/openapi.yaml

clean:
	rm -rf $(BIN_DIR) coverage.out

help: ## list targets
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
