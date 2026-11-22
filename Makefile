.PHONY: all build setup run test test-unit clean quality fmt fmt-check go-mod-tidy lint lint-install help

all: build

build:
	go build -o tls-client-scanner ./cmd/tls-client-scanner

setup: test/cert.pem test/key.pem test/mldsa.pem test/mldsa.key

# Only generate the certificates if they are missing.
test/cert.pem test/key.pem:
	@mkdir -p test
	@openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -noenc \
		-out test/cert.pem \
		-keyout test/key.pem \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

test/mldsa.pem test/mldsa.key:
	@mkdir -p test
	@openssl req -x509 -newkey mldsa65 -provparam ml-dsa.output_formats=seed-only -sha256 -days 3650 -noenc \
		-out test/mldsa.pem \
		-keyout test/mldsa.key \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

run: setup build
	@./tls-client-scanner \
  		-address 127.0.0.1:8443 \
		-cert test/cert.pem \
		-key test/key.pem

run_mldsa: setup build
	@./tls-client-scanner \
  		-address 127.0.0.1:8443 \
		-cert test/mldsa.pem \
		-key test/mldsa.key

test: quality test-unit

test-unit:
	@go test -race -v ./...

# Clean build artifacts
clean:
	rm -f tls-client-scanner
	go clean

# Run linting with golangci-lint
lint:
	golangci-lint run --timeout=5m

# Run linting with golangci-lint (install if not present)
lint-install:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest; \
	fi
	golangci-lint run --timeout=5m

# Check code formatting
fmt-check:
	@if [ "$(shell gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted. Please run 'gofmt -s -w .'"; \
		gofmt -s -l .; \
		exit 1; \
	fi
	@echo "Code formatting is correct"

go-mod-tidy:
	@go mod tidy
	@if ! git diff --exit-code -- go.mod go.sum >/dev/null; then \
		echo "go.mod or go.sum is not tidy. Please run 'go mod tidy'"; \
		exit 1; \
	fi
	@echo "go.mod and go.sum are tidy"

# Format code
fmt:
	gofmt -s -w .

# Run all code quality checks
quality: fmt-check go-mod-tidy lint
	@echo "All code quality checks passed!"

help:
	@echo "Available targets:"
	@echo "  build               - Build tls-client-scanner"
	@echo "  test                - Run quality checks and tests"
	@echo "  test-unit           - Run unit tests"
	@echo "  clean               - Clean build artifacts"
	@echo ""
	@echo "Code Quality:"
	@echo "  quality             - Run all code quality checks"
	@echo "  lint                - Run golangci-lint"
	@echo "  lint-install        - Install golangci-lint and run linting"
	@echo "  fmt-check           - Check code formatting"
	@echo "  fmt                 - Format code with gofmt"
	@echo "  go-mod-tidy         - Check if go.mod is tidy"
	@echo "  help                - Show this help"
