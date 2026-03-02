import { test, expect } from "@playwright/test";

/**
 * Token Refresh Grant e2e specs.
 *
 * Covers POST /oauth2/token with grant_type=refresh_token (RFC 6749 §6).
 * Tests the full Refresh Token flow: authorization code flow → initial token
 * exchange (to obtain a refresh_token) → refresh token grant → token rotation
 * validation.
 *
 * All tests in this file are skipped (DLD-676) until the Refresh Token
 * grant factory (compose.OAuth2RefreshTokenGrantFactory) is registered and
 * confirmed to be working end-to-end.  Remove each `test.skip()` call once
 * the corresponding server-side feature is in place.
 *
 * Prerequisites (already satisfied per codebase analysis):
 *   - compose.OAuth2RefreshTokenGrantFactory registered in main.go
 *   - test-client has grant_type=refresh_token registered
 *     (internal/testhelper/server.go)
 *   - fosite config has RefreshTokenLifespan: 24 * time.Hour
 *
 * Prerequisites for the expired-token test (not yet satisfied):
 *   - A mechanism to issue or simulate a refresh_token with a very short
 *     lifespan (e.g. RefreshTokenLifespan=1s in the test server config), or
 *     a test API that advances the server clock.
 *     When activating that test, set a short lifespan and add:
 *       await page.waitForTimeout(2000);
 *
 * Parent issue: DLD-577 (MyAuth — 개인 인프라용 OAuth/OIDC Server)
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const VALID_CLIENT_ID = "test-client";
const VALID_CLIENT_SECRET = "test-secret";
const VALID_REDIRECT_URI = "http://localhost:9000/callback";
const VALID_SCOPE = "openid profile email";
const VALID_STATE = "test-state-token-668";
const VALID_NONCE = "test-nonce-token-668";

const TOKEN_ENDPOINT = "/oauth2/token";

// ---------------------------------------------------------------------------
// Helper: obtain an authorization code via login → consent approve flow.
//
// Uses the { page, context } fixture pattern from authorize.spec.ts because
// the { request } fixture does not share cookies across calls.
// ---------------------------------------------------------------------------

/**
 * Performs the full login → consent-approve flow and returns the
 * authorization code extracted from the redirect Location header.
 *
 * @param page    Playwright Page object (carries browser session)
 * @param context Playwright BrowserContext (used to read session cookies)
 * @param nonce   OIDC nonce value to include in the authorization request
 * @returns authorization code string
 */
async function obtainAuthorizationCode(
  page: import("@playwright/test").Page,
  context: import("@playwright/test").BrowserContext,
  nonce: string = VALID_NONCE
): Promise<string> {
  // Step 1 — log in to establish a session cookie.
  await page.goto("/login");
  await page.getByLabel("Email").fill("admin@test.local");
  await page.getByLabel("Password").fill("test-password");
  await page.getByRole("button", { name: /log\s*in/i }).click();

  // Step 2 — navigate to the authorization endpoint so the consent page
  // is rendered and the server associates the auth request with the session.
  const authParams = new URLSearchParams({
    response_type: "code",
    client_id: VALID_CLIENT_ID,
    redirect_uri: VALID_REDIRECT_URI,
    scope: VALID_SCOPE,
    state: VALID_STATE,
    nonce,
  });
  await page.goto(`/oauth2/auth?${authParams.toString()}`);
  await expect(
    page.getByRole("button", { name: /승인|approve/i })
  ).toBeVisible();

  // Step 3 — send the approve POST with the session cookie so the server
  // issues an authorization code.
  const cookies = await context.cookies();
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");

  const response = await page.request.post(
    `/oauth2/auth?${authParams.toString()}`,
    {
      headers: {
        cookie: cookieHeader,
        "content-type": "application/x-www-form-urlencoded",
      },
      data: "action=approve",
      maxRedirects: 0,
    }
  );

  expect([302, 303]).toContain(response.status());

  const location = response.headers()["location"] ?? "";
  expect(location).toContain(VALID_REDIRECT_URI);

  const redirected = new URL(location);
  const code = redirected.searchParams.get("code");
  expect(code).toBeTruthy();

  return code as string;
}

// ---------------------------------------------------------------------------
// Helper: build Basic Auth header for client_secret_basic authentication.
// ---------------------------------------------------------------------------

function basicAuthHeader(clientId: string, clientSecret: string): string {
  const encoded = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64"
  );
  return `Basic ${encoded}`;
}

// ---------------------------------------------------------------------------
// Helper: decode a JWT without signature verification (test-only utility).
// Returns the parsed header and payload objects.
// ---------------------------------------------------------------------------

function decodeJwtUnsafe(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(`Not a valid JWT — expected 3 parts, got ${parts.length}`);
  }
  const decode = (segment: string): Record<string, unknown> =>
    JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  return { header: decode(parts[0]), payload: decode(parts[1]) };
}

// ---------------------------------------------------------------------------
// Helper: perform the full authorization code flow and exchange it for tokens,
// returning the initial token response body including the refresh_token.
//
// This is the prerequisite step for all refresh token tests: a refresh_token
// can only be obtained after a successful authorization_code token exchange.
// ---------------------------------------------------------------------------

/**
 * Completes the authorization code flow and returns the token response body.
 * The returned object contains access_token, id_token, and refresh_token.
 *
 * @param page    Playwright Page object (carries browser session)
 * @param context Playwright BrowserContext (used to read session cookies)
 * @returns parsed token endpoint response body
 */
async function obtainInitialTokens(
  page: import("@playwright/test").Page,
  context: import("@playwright/test").BrowserContext
): Promise<Record<string, unknown>> {
  const code = await obtainAuthorizationCode(page, context);

  const response = await page.request.post(TOKEN_ENDPOINT, {
    headers: {
      Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    data: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: VALID_REDIRECT_URI,
    }).toString(),
  });

  expect(response.status()).toBe(200);
  const body = await response.json();

  // Verify the initial exchange returned a refresh_token before proceeding.
  expect(typeof body.refresh_token).toBe("string");
  expect((body.refresh_token as string).length).toBeGreaterThan(0);

  return body as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 1. Happy path — refresh_token → 새 access_token + 새 refresh_token 수신
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — refresh_token happy path", () => {
  test(
    "issues a new access_token and a new refresh_token when a valid refresh_token is presented",
    async ({ page, context }) => {
      // TODO: Activate when DLD-676 is implemented
      test.skip();

      // Arrange — complete the authorization code flow to obtain a refresh_token.
      const initialTokens = await obtainInitialTokens(page, context);
      const refreshToken = initialTokens.refresh_token as string;

      // Act — use the refresh_token to request a new set of tokens.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }).toString(),
      });

      // Assert — RFC 6749 §6 requires HTTP 200 with a new access_token.
      expect(response.status()).toBe(200);

      const body = await response.json();

      // A new access_token must be present and non-empty.
      expect(typeof body.access_token).toBe("string");
      expect(body.access_token.length).toBeGreaterThan(0);

      // The new access_token must differ from the original one (fresh token).
      expect(body.access_token).not.toBe(initialTokens.access_token);

      // A new refresh_token must be present and non-empty (token rotation).
      expect(typeof body.refresh_token).toBe("string");
      expect(body.refresh_token.length).toBeGreaterThan(0);

      // token_type must be "Bearer" (RFC 6749 §7.1).
      expect(body.token_type).toMatch(/^bearer$/i);

      // expires_in must be a positive integer.
      expect(typeof body.expires_in).toBe("number");
      expect(body.expires_in).toBeGreaterThan(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 2. 새 access_token JWT claim 검증 — refresh 후 발급된 토큰의 유효성 확인
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — refresh_token access_token claims", () => {
  test(
    "new access_token is a valid JWT with correct iss, aud, scope, and exp claims",
    async ({ page, context }) => {
      // TODO: Activate when DLD-676 is implemented
      test.skip();

      // Arrange — obtain initial tokens via authorization code flow.
      const initialTokens = await obtainInitialTokens(page, context);
      const refreshToken = initialTokens.refresh_token as string;

      // Act — exchange the refresh_token for new tokens.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }).toString(),
      });

      expect(response.status()).toBe(200);
      const body = await response.json();

      // Decode the new access_token JWT without verifying the signature.
      const { header, payload } = decodeJwtUnsafe(body.access_token as string);

      // Assert — header must indicate RS256 signing algorithm.
      expect(header.alg).toBe("RS256");
      expect(typeof header.kid).toBe("string");
      expect((header.kid as string).length).toBeGreaterThan(0);

      // iss must match the configured issuer.
      expect(payload.iss).toBe("https://auth.test.local");

      // aud must contain the client_id.
      const aud = Array.isArray(payload.aud)
        ? payload.aud
        : [payload.aud];
      expect(aud).toContain(VALID_CLIENT_ID);

      // scope must include the originally requested scopes.
      const scopeValue = payload.scope as string;
      expect(scopeValue).toContain("openid");
      expect(scopeValue).toContain("profile");
      expect(scopeValue).toContain("email");

      // exp must be a future Unix timestamp.
      const nowSeconds = Math.floor(Date.now() / 1000);
      expect(typeof payload.exp).toBe("number");
      expect(payload.exp as number).toBeGreaterThan(nowSeconds);

      // iat must be a past or present Unix timestamp.
      expect(typeof payload.iat).toBe("number");
      expect(payload.iat as number).toBeLessThanOrEqual(nowSeconds + 5);
    }
  );
});

// ---------------------------------------------------------------------------
// 3. Token rotation — 사용된 refresh_token 재사용 불가 (invalid_grant)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — refresh_token rotation: reuse rejected", () => {
  test(
    "returns 400 invalid_grant when an already-used refresh_token is presented again",
    async ({ page, context }) => {
      // TODO: Activate when DLD-676 is implemented
      test.skip();

      // Arrange — obtain initial tokens via authorization code flow.
      const initialTokens = await obtainInitialTokens(page, context);
      const originalRefreshToken = initialTokens.refresh_token as string;

      // Act — first refresh must succeed and consume the original refresh_token.
      const firstRefreshResponse = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: originalRefreshToken,
        }).toString(),
      });
      expect(firstRefreshResponse.status()).toBe(200);

      // Act — second refresh using the same (now-rotated) refresh_token must fail.
      // RFC 6749 §6 and fosite's token rotation require that each refresh_token
      // is single-use; the original token is invalidated upon first use.
      const secondRefreshResponse = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: originalRefreshToken,
        }).toString(),
      });

      // Assert — the replayed refresh_token must be rejected with 400 invalid_grant.
      expect(secondRefreshResponse.status()).toBe(400);
      const body = await secondRefreshResponse.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});

// ---------------------------------------------------------------------------
// 4. 만료된 refresh_token 사용 → 에러 응답
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — refresh_token error: expired token", () => {
  test(
    "returns an error when an expired refresh_token is presented",
    async ({ page, context }) => {
      // TODO: Activate when DLD-676 is implemented
      test.skip();

      // Arrange — obtain initial tokens via authorization code flow.
      const initialTokens = await obtainInitialTokens(page, context);
      const refreshToken = initialTokens.refresh_token as string;

      // Simulate expiry by waiting longer than the server's RefreshTokenLifespan.
      // In a real test run this requires either:
      //   a) Setting RefreshTokenLifespan=1s in the test server config and then:
      //        await page.waitForTimeout(2000);
      //   b) A test API that advances the server clock past the token's exp claim.
      //
      // When activating this test:
      //   1. Configure the test server with RefreshTokenLifespan=1s.
      //   2. Uncomment the waitForTimeout call below.
      //   3. Remove the test.skip() call at the top of this test.
      //
      // await page.waitForTimeout(2000);

      // Act — attempt to use the refresh_token after its lifespan has elapsed.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }).toString(),
      });

      // Assert — the server must reject the expired refresh_token.
      // RFC 6749 §5.2 requires an error response; invalid_grant is the expected
      // error code for an expired token (fosite behavior confirmed).
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});

// ---------------------------------------------------------------------------
// 5. 알 수 없는 refresh_token → invalid_grant 에러
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — refresh_token error: unknown token", () => {
  test(
    "returns 400 invalid_grant when a completely unknown refresh_token is presented",
    async ({ page }) => {
      // TODO: Activate when DLD-676 is implemented
      test.skip();

      // Act — submit a fabricated refresh_token that was never issued by the server.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: "this-refresh-token-does-not-exist-00000000000000",
        }).toString(),
      });

      // Assert — RFC 6749 §5.2 requires 400 with error=invalid_grant when the
      // refresh_token is not recognized by the authorization server.
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});
