.PHONY: test test-e2e dev build lint

# Run all Go unit and integration tests with race detection.
# -count=1 disables the test result cache so each run is fresh.
test:
	go test -v -race -count=1 ./...

# Run Playwright e2e tests.
# The Go server is started automatically by playwright.config.ts (webServer option).
test-e2e:
	npx playwright test

# Start the development server (Go run, live-reloads not included).
dev:
	go run ./cmd/server

# Build a stripped, reproducible binary into bin/my-auth.
build:
	go build -ldflags="-s -w" -trimpath -o bin/my-auth ./cmd/server

# Run static analysis.
lint:
	go vet ./...
