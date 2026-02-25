import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for my-auth Admin UI e2e tests.
 *
 * The Go server lifecycle is managed as follows:
 *
 *   Local dev  — `npx playwright test` launches `go run ./cmd/server` via
 *                webServer. If a server is already listening on :8080 it is
 *                reused (reuseExistingServer: true).
 *
 *   CI         — The workflow builds the binary, starts it in the background,
 *                then runs Playwright with PLAYWRIGHT_REUSE_SERVER=1 so that
 *                Playwright connects to the already-running process instead of
 *                trying to spawn another one.
 *
 * @see https://playwright.dev/docs/test-configuration
 */

const reuseExistingServer =
  !process.env.CI || process.env.PLAYWRIGHT_REUSE_SERVER === "1";

export default defineConfig({
  testDir: "./e2e",

  /* Run tests in files in parallel */
  fullyParallel: false,

  /* Fail the build on CI if test.only() is used accidentally */
  forbidOnly: !!process.env.CI,

  /* Retry on CI only */
  retries: process.env.CI ? 1 : 0,

  /* Single worker so the Go server is not hammered by concurrent tests */
  workers: 1,

  /* Reporter: dot in CI, html locally */
  reporter: process.env.CI ? "dot" : "html",

  use: {
    /* Base URL used by page.goto('/some-path') */
    baseURL: "http://localhost:8080",

    /* Collect trace on first retry to simplify post-mortem debugging */
    trace: "on-first-retry",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  /**
   * Launch the Go development server before running tests.
   *
   * In CI the server binary is pre-built and started in a background step so
   * that reuseExistingServer: true applies and Playwright does not try to
   * spawn `go run` inside the test runner process.
   */
  webServer: {
    command: "go run ./cmd/server",
    url: "http://localhost:8080/healthz",
    reuseExistingServer,
    timeout: 30 * 1000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
