import { test, expect } from "@playwright/test";

/**
 * Authorization Endpoint & Consent e2e specs.
 *
 * Covers GET /oauth2/auth (unauthenticated redirect, consent page rendering,
 * consent page UI) and POST /oauth2/auth (approve, deny, error cases).
 *
 * All tests in this file are skipped until the authorization endpoint and
 * consent flow are fully implemented.
 */

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const VALID_CLIENT_ID = "test-client";
const VALID_REDIRECT_URI = "http://localhost:9000/callback";
const VALID_SCOPE = "openid profile email";
const VALID_STATE = "test-state-abc123";

/** Builds the /oauth2/auth query string with all required RFC 6749 parameters. */
function authQuery(overrides: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: VALID_CLIENT_ID,
    redirect_uri: VALID_REDIRECT_URI,
    scope: VALID_SCOPE,
    state: VALID_STATE,
    ...overrides,
  });
  return `/oauth2/auth?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// 1. Unauthenticated request → redirect to /login
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/auth — unauthenticated", () => {
  test(
    "redirects to /login with return_to preserving the original URL",
    async ({ request }) => {
      // Arrange
      const originalUrl = authQuery();

      // Act — follow redirects disabled so we can inspect the 302 itself.
      const response = await request.get(originalUrl, {
        maxRedirects: 0,
      });

      // Assert — must be a 302 redirect to the login page.
      expect(response.status()).toBe(302);

      const location = response.headers()["location"] ?? "";
      expect(location).toContain("/login");

      // The original authorization URL must be preserved in return_to so the
      // user lands back on the consent page after successful login.
      const locationUrl = new URL(location, "http://localhost:8080");
      const returnTo = locationUrl.searchParams.get("return_to") ?? "";
      expect(returnTo).toContain("/oauth2/auth");
      expect(returnTo).toContain("response_type=code");
      expect(returnTo).toContain(`client_id=${VALID_CLIENT_ID}`);
    }
  );
});

// ---------------------------------------------------------------------------
// 2. Authenticated request → consent page rendered
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/auth — authenticated", () => {
  test(
    "renders the consent page when the user is already logged in",
    async ({ page }) => {
      // Arrange — establish an authenticated session via the login endpoint.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      // Act — navigate to the authorization endpoint while authenticated.
      await page.goto(authQuery());

      // Assert — the consent page must be rendered (not another redirect to
      // /login) and must contain an approve action.
      await expect(page).toHaveURL(/\/oauth2\/auth/);
      await expect(
        page.getByRole("button", { name: /승인|approve/i })
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 3. Consent page UI elements
// ---------------------------------------------------------------------------

test.describe("Consent page UI", () => {
  test(
    "displays client name, domain, and the requested scopes",
    async ({ page }) => {
      // Arrange — log in first.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      // Act
      await page.goto(authQuery());

      // Assert — client identity section.
      await expect(page.getByText(VALID_CLIENT_ID)).toBeVisible();

      // Assert — all three requested scopes must appear as individual cards
      // with their human-readable names.
      await expect(page.getByText("openid")).toBeVisible();
      await expect(page.getByText("profile")).toBeVisible();
      await expect(page.getByText("email")).toBeVisible();

      // Assert — both action buttons must be present.
      await expect(
        page.getByRole("button", { name: /거부|deny/i })
      ).toBeVisible();
      await expect(
        page.getByRole("button", { name: /승인|approve/i })
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 4. POST /oauth2/auth — user approves consent
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/auth — approve", () => {
  test(
    "redirects to callback URL with code parameter after user approves",
    async ({ page }) => {
      // Arrange — log in first.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      // Navigate to the consent page.
      await page.goto(authQuery());

      // Set up a route handler to intercept navigation to the redirect URI
      // (localhost:9000). The route must be fully registered (awaited) before
      // clicking the button to avoid a race condition.
      let resolveRedirect!: (url: string) => void;
      const redirectUrl = new Promise<string>((resolve) => {
        resolveRedirect = resolve;
      });

      await page.route("http://localhost:9000/**", (route) => {
        resolveRedirect(route.request().url());
        route.abort();
      });

      // Act — click the approve button, which submits POST /oauth2/auth.
      await page.getByRole("button", { name: /승인|approve/i }).click();

      // Assert — the server must have redirected to the client's redirect_uri
      // carrying the authorization code.
      const url = await redirectUrl;
      const redirected = new URL(url);
      expect(redirected.searchParams.get("code")).toBeTruthy();
      expect(redirected.searchParams.get("state")).toBe(VALID_STATE);
    }
  );
});

// ---------------------------------------------------------------------------
// 5. POST /oauth2/auth — user denies consent
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/auth — deny", () => {
  test(
    "returns access_denied error after user denies consent",
    async ({ page }) => {
      // Arrange — log in first.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      // Navigate to the consent page.
      await page.goto(authQuery());

      // Set up a route handler to intercept navigation to the redirect URI.
      let resolveRedirect!: (url: string) => void;
      const redirectUrl = new Promise<string>((resolve) => {
        resolveRedirect = resolve;
      });

      await page.route("http://localhost:9000/**", (route) => {
        resolveRedirect(route.request().url());
        route.abort();
      });

      // Act — click the deny button.
      await page.getByRole("button", { name: /거부|deny/i }).click();

      // Assert — RFC 6749 §4.1.2.1: the server MUST redirect to redirect_uri
      // with error=access_denied.
      const url = await redirectUrl;
      const redirected = new URL(url);
      expect(redirected.searchParams.get("error")).toBe("access_denied");
      expect(redirected.searchParams.get("state")).toBe(VALID_STATE);
    }
  );
});

// ---------------------------------------------------------------------------
// 6. Error cases — invalid client_id and invalid redirect_uri
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/auth — error cases", () => {
  test(
    "returns an error response when client_id is unknown",
    async ({ request }) => {
      // Act — fosite must NOT redirect to an unrecognised client's redirect_uri;
      // it returns an error directly to the user-agent (RFC 6749 §4.1.2.1).
      const response = await request.get(
        authQuery({ client_id: "nonexistent-client-id" }),
        { maxRedirects: 0 }
      );

      // Assert — any non-2xx, non-redirect or an error page body is acceptable;
      // the key requirement is that the request does not succeed with 200.
      expect(response.status()).not.toBe(200);
    }
  );

  test(
    "returns an error response when redirect_uri does not match the registered URI",
    async ({ request }) => {
      // Act — fosite must reject a mismatched redirect_uri and return the error
      // directly rather than redirecting (RFC 6749 §4.1.2.1 security note).
      const response = await request.get(
        authQuery({ redirect_uri: "http://evil.example.com/callback" }),
        { maxRedirects: 0 }
      );

      // Assert — the server must not redirect to the attacker-controlled URI.
      const location = response.headers()["location"] ?? "";
      expect(location).not.toContain("evil.example.com");
      expect(response.status()).not.toBe(200);
    }
  );
});
