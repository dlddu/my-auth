.PHONY: test test-e2e dev build build-spa lint

# Build the admin SPA (Vite + React + TypeScript).
# Outputs to internal/handler/admin/dist/ for go:embed.
build-spa:
	cd admin-spa && npm ci && npm run build

# Run all Go unit and integration tests with race detection.
# -count=1 disables the test result cache so each run is fresh.
test: build-spa
	go test -v -race -count=1 ./...

# Run Playwright e2e tests.
# The Go server is started automatically by playwright.config.ts (webServer option).
test-e2e: build-spa
	npx playwright test

# Start the development server (Go run, live-reloads not included).
dev: build-spa
	go run ./cmd/server

# Build a stripped, reproducible binary into bin/my-auth.
build: build-spa
	go build -ldflags="-s -w" -trimpath -o bin/my-auth ./cmd/server

# Run static analysis.
lint:
	go vet ./...
