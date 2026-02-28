import { test, expect } from "@playwright/test";

/**
 * Example e2e spec — basic server health check.
 *
 * Tests cover the basic server health check endpoint.
 */

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

test.describe("Server health check", () => {
  test("GET /healthz returns 200 ok", async ({ page }) => {
    // Act
    const response = await page.goto("/healthz");

    // Assert
    expect(response).not.toBeNull();
    expect(response!.status()).toBe(200);

    const body = await response!.text();
    expect(body).toBe("ok");
  });

  test("server responds within acceptable time", async ({ page }) => {
    // Arrange
    const start = Date.now();

    // Act
    await page.goto("/healthz");

    // Assert — round-trip must complete within 1 second for a local server.
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(1000);
  });
});
