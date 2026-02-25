import { test, expect } from "@playwright/test";

/**
 * Example e2e spec — basic server health check.
 *
 * All tests in this file are skipped (DLD-579) until the server delivers a
 * real HTTP response on the health-check endpoint.  Remove the `test.skip()`
 * calls once the server is implemented.
 *
 * TODO: Activate when DLD-579 is implemented.
 */

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

test.describe("Server health check", () => {
  test("GET /healthz returns 200 ok", async ({ page }) => {
    // TODO: Activate when DLD-579 is implemented
    test.skip();

    // Act
    const response = await page.goto("/healthz");

    // Assert
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(200);

    const body = await response!.text();
    expect(body).toBe("ok");
  });

  test("server responds within acceptable time", async ({ page }) => {
    // TODO: Activate when DLD-579 is implemented
    test.skip();

    // Arrange
    const start = Date.now();

    // Act
    await page.goto("/healthz");

    // Assert — round-trip must complete within 1 second for a local server.
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(1000);
  });
});
