MODULE   := github.com/hanej/passport
BINARY   := passport
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")
GOFLAGS  := -trimpath -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build build-all run test test-coverage test-integration test-e2e lint fmt vet docker rpm-amd64 rpm-arm64 clean help

## Build

build: ## Build for current platform
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/passport

build-all: ## Cross-compile for linux/amd64, linux/arm64, windows/amd64
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/passport
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY)-linux-arm64 ./cmd/passport
#	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY)-windows-amd64.exe ./cmd/passport

## RPM Packaging

rpm-amd64: ## Build RPM for linux/amd64 (requires nfpm)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/passport
	VERSION=$(VERSION) nfpm pkg --packager rpm --config nfpm.yaml --target dist/

rpm-arm64: ## Build RPM for linux/arm64 (requires nfpm)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/passport
	VERSION=$(VERSION) nfpm pkg --packager rpm --config nfpm.yaml --target dist/

## Run

run: ## Build and run with example config
	go run ./cmd/passport -config config.yaml

## Test

test: ## Run unit tests
	CGO_ENABLED=0 go test ./... -count=1

test-race: ## Run unit tests with race detector
	go test ./... -count=1 -race

test-coverage: ## Run tests with coverage, fail if below 95%
	CGO_ENABLED=0 PKGS="$$(go list ./... | grep -v '^github.com/hanej/passport/cmd/passport$$' | grep -v '^github.com/hanej/passport/internal/db$$')"; go test $$PKGS -coverprofile=coverage.out -count=1
	go tool cover -func=coverage.out
	@awk '/^total:/ { gsub(/%/,"",$$3); if ($$3+0 < 95.0) { print "FAIL: coverage " $$3 "% < 95%"; exit 1 } else { print "OK: coverage " $$3 "%" } }' coverage.out

test-coverage-html: test-coverage ## Open coverage report in browser
	go tool cover -html=coverage.out -o coverage.html

test-integration: ## Run integration tests
	CGO_ENABLED=0 go test ./... -tags=integration -count=1 -race

test-e2e: ## Run end-to-end tests
	CGO_ENABLED=0 go test ./... -tags=e2e -count=1 -timeout=120s

## Code Quality

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format code
	gofmt -w .

vet: ## Run go vet
	go vet ./...

## Docker

docker: ## Build Docker image
	docker build -t passport:latest .

## Cleanup

clean: ## Remove build artifacts
	rm -rf bin/ dist/ coverage.out coverage.html

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
