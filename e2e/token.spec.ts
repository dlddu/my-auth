import { test, expect } from "@playwright/test";

/**
 * Token Endpoint e2e specs.
 *
 * Covers POST /oauth2/token with grant_type=authorization_code.
 * Tests the full Authorization Code flow: login → consent approval → code
 * extraction → token exchange → token validation.
 *
 * All tests in this file are skipped (DLD-668) until the token endpoint is
 * implemented and the /oauth2/token route is registered in the server.
 * Remove the `test.skip()` calls once the endpoint is available.
 *
 * TODO: Activate when DLD-668 is implemented.
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
// 1. Happy path — authorization code → token exchange → 3 tokens received
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — happy path", () => {
  test(
    "exchanges a valid authorization code for access_token, id_token, and refresh_token",
    async ({ page, context }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Arrange — obtain a fresh authorization code via the consent flow.
      const code = await obtainAuthorizationCode(page, context);

      // Act — exchange the code for tokens using client_secret_basic auth.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: VALID_REDIRECT_URI,
        }).toString(),
      });

      // Assert — the token endpoint must return HTTP 200.
      expect(response.status()).toBe(200);

      const body = await response.json();

      // All three token types must be present and non-empty.
      expect(typeof body.access_token).toBe("string");
      expect(body.access_token.length).toBeGreaterThan(0);

      expect(typeof body.id_token).toBe("string");
      expect(body.id_token.length).toBeGreaterThan(0);

      expect(typeof body.refresh_token).toBe("string");
      expect(body.refresh_token.length).toBeGreaterThan(0);

      // token_type must be "Bearer" (case-insensitive per RFC 6749 §7.1).
      expect(body.token_type).toMatch(/^bearer$/i);

      // expires_in must be a positive integer.
      expect(typeof body.expires_in).toBe("number");
      expect(body.expires_in).toBeGreaterThan(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 2. JWT access_token claim validation
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — JWT access_token claims", () => {
  test(
    "access_token is a JWT with valid iss, aud, scope, and exp claims",
    async ({ page, context }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Arrange
      const code = await obtainAuthorizationCode(page, context);

      // Act
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
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

      // Decode the access_token JWT without verifying the signature
      // (signature verification is covered separately via JWKS).
      const { header, payload } = decodeJwtUnsafe(body.access_token);

      // Assert — header must indicate RS256 signing algorithm.
      expect(header.alg).toBe("RS256");
      expect(typeof header.kid).toBe("string");
      expect((header.kid as string).length).toBeGreaterThan(0);

      // iss must match the configured issuer.
      expect(payload.iss).toBe("http://localhost:8080");

      // aud must contain the client_id.
      const aud = Array.isArray(payload.aud)
        ? payload.aud
        : [payload.aud];
      expect(aud).toContain(VALID_CLIENT_ID);

      // scope must include all requested scopes.
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
// 3. OIDC id_token JWKS signature verification and claim validation
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — id_token OIDC claims", () => {
  test(
    "id_token JWT header references a kid present in the JWKS endpoint",
    async ({ page, context }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Arrange
      const code = await obtainAuthorizationCode(page, context);

      // Act — exchange code for tokens.
      const tokenResponse = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: VALID_REDIRECT_URI,
        }).toString(),
      });

      expect(tokenResponse.status()).toBe(200);
      const tokenBody = await tokenResponse.json();

      const { header } = decodeJwtUnsafe(tokenBody.id_token);

      // Fetch the JWKS and confirm the id_token's kid is present.
      const jwksResponse = await page.request.get("/jwks");
      expect(jwksResponse.status()).toBe(200);
      const jwks = await jwksResponse.json();

      const matchingKey = (
        jwks.keys as Array<Record<string, unknown>>
      ).find((k) => k.kid === header.kid);

      expect(matchingKey).toBeDefined();
      // The matching key must be an RSA public key suitable for RS256 verification.
      expect(matchingKey!.kty).toBe("RSA");
      expect(matchingKey!.alg).toBe("RS256");
      expect(matchingKey!.use).toBe("sig");
    }
  );

  test(
    "id_token contains valid sub, aud, iss, nonce, and at_hash claims",
    async ({ page, context }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Arrange — use a specific nonce so we can verify it is echoed back.
      const nonce = "e2e-nonce-dld668-idtoken";
      const code = await obtainAuthorizationCode(page, context, nonce);

      // Act
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
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

      const { payload } = decodeJwtUnsafe(body.id_token);

      // iss — must match the configured issuer.
      expect(payload.iss).toBe("http://localhost:8080");

      // aud — must contain the client_id (may be string or array).
      const aud = Array.isArray(payload.aud)
        ? payload.aud
        : [payload.aud];
      expect(aud).toContain(VALID_CLIENT_ID);

      // sub — must be a non-empty string identifying the user.
      expect(typeof payload.sub).toBe("string");
      expect((payload.sub as string).length).toBeGreaterThan(0);

      // nonce — must be echoed back unchanged (OIDC Core §3.1.3.7).
      expect(payload.nonce).toBe(nonce);

      // at_hash — must be present when an access_token is issued alongside
      // the id_token (OIDC Core §3.3.2.11).
      expect(typeof payload.at_hash).toBe("string");
      expect((payload.at_hash as string).length).toBeGreaterThan(0);

      // exp — must be a future Unix timestamp.
      const nowSeconds = Math.floor(Date.now() / 1000);
      expect(typeof payload.exp).toBe("number");
      expect(payload.exp as number).toBeGreaterThan(nowSeconds);
    }
  );
});

// ---------------------------------------------------------------------------
// 4. Opaque refresh_token validation
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — refresh_token", () => {
  test(
    "refresh_token is opaque (not a JWT) and has sufficient entropy",
    async ({ page, context }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Arrange
      const code = await obtainAuthorizationCode(page, context);

      // Act
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
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

      const refreshToken: string = body.refresh_token;
      expect(typeof refreshToken).toBe("string");
      // Opaque tokens must not be parseable as a three-part JWT.
      expect(refreshToken.split(".").length).not.toBe(3);
      // Must have meaningful length (at least 20 characters of entropy).
      expect(refreshToken.length).toBeGreaterThanOrEqual(20);
    }
  );
});

// ---------------------------------------------------------------------------
// 5. Error case — invalid authorization code
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — error: invalid code", () => {
  test(
    "returns 400 invalid_grant when the authorization code is unknown",
    async ({ page }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Act — submit a completely fabricated code that was never issued.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code: "this-code-does-not-exist-00000000",
          redirect_uri: VALID_REDIRECT_URI,
        }).toString(),
      });

      // Assert — RFC 6749 §5.2 requires 400 with error=invalid_grant.
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});

// ---------------------------------------------------------------------------
// 6. Error case — expired authorization code
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — error: expired code", () => {
  test(
    "returns 400 invalid_grant when the authorization code has expired",
    async ({ page, context }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Arrange — obtain a real code.
      const code = await obtainAuthorizationCode(page, context);

      // Simulate expiry by waiting longer than the server's
      // AuthorizeCodeLifespan (configured as 10 minutes in main.go).
      // In a real test run this would be replaced by either:
      //   a) A test API that advances the server clock, or
      //   b) A server configuration that sets a very short lifespan (e.g. 1 s).
      // For the skip-state spec we simply document the intent without
      // blocking on a real time.sleep call.
      //
      // When activating, set AuthorizeCodeLifespan=1s in the test server
      // config and add: await page.waitForTimeout(2000);

      // Act — try to use the code after its lifespan has elapsed.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: VALID_REDIRECT_URI,
        }).toString(),
        // NOTE: Remove the timeout override below when activating this test.
        // The actual exchange here will succeed because the code has not
        // genuinely expired; that is intentional while the test is skipped.
      });

      // Assert — server must reject the expired code with 400 invalid_grant.
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});

// ---------------------------------------------------------------------------
// 7. Error case — authorization code reuse (replay attack prevention)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — error: code reuse", () => {
  test(
    "returns 400 invalid_grant on the second use of an already-redeemed authorization code",
    async ({ page, context }) => {
      // TODO: Activate when DLD-668 is implemented
      test.skip();

      // Arrange — obtain a real authorization code.
      const code = await obtainAuthorizationCode(page, context);

      const tokenRequestParams = {
        headers: {
          Authorization: basicAuthHeader(
            VALID_CLIENT_ID,
            VALID_CLIENT_SECRET
          ),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: VALID_REDIRECT_URI,
        }).toString(),
      };

      // Act — first exchange must succeed.
      const firstResponse = await page.request.post(
        TOKEN_ENDPOINT,
        tokenRequestParams
      );
      expect(firstResponse.status()).toBe(200);

      // Act — second exchange with the same code must be rejected.
      // RFC 6749 §4.1.2 and fosite require single-use codes.
      const secondResponse = await page.request.post(
        TOKEN_ENDPOINT,
        tokenRequestParams
      );

      // Assert — replayed code must be rejected with 400 invalid_grant.
      expect(secondResponse.status()).toBe(400);
      const body = await secondResponse.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});
