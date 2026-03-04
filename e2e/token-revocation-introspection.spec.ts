import { test, expect } from "@playwright/test";

/**
 * Token Revocation and Introspection e2e specs.
 *
 * Covers POST /oauth2/revoke (RFC 7009) and POST /oauth2/introspect (RFC 7662).
 * Tests the full revocation and introspection flow: authorization code flow →
 * initial token exchange (to obtain access_token) → revocation or introspection
 * of the resulting token.
 *
 * All tests in this file are skipped (DLD-678) until the revocation and
 * introspection endpoints are registered in the router.
 * Remove each `test.skip()` call once the corresponding server-side feature
 * is in place.
 *
 * Prerequisites (not yet satisfied — hence the skips):
 *   - POST /oauth2/revoke endpoint registered (fosite RevocationEndpoint handler)
 *   - POST /oauth2/introspect endpoint registered (fosite IntrospectionEndpoint handler)
 *   - test-client has grant_type=refresh_token registered (already satisfied)
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
const VALID_STATE = "test-state-token-678";
const VALID_NONCE = "test-nonce-token-678";

const TOKEN_ENDPOINT = "/oauth2/token";
const REVOKE_ENDPOINT = "/oauth2/revoke";
const INTROSPECT_ENDPOINT = "/oauth2/introspect";

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
// Helper: obtain an authorization code via login → consent approve flow.
//
// Uses the { page, context } fixture pattern because the { request } fixture
// does not share cookies across calls.
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
// Helper: complete the authorization code flow and return the token response
// body including access_token and refresh_token.
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

  // Verify the initial exchange returned an access_token before proceeding.
  expect(typeof body.access_token).toBe("string");
  expect((body.access_token as string).length).toBeGreaterThan(0);

  return body as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 1. Revocation happy path — valid access_token 폐기 → introspect active: false
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/revoke — revocation happy path", () => {
  test(
    "returns 200 for a valid access_token, then introspecting the token yields active: false",
    async ({ page, context }) => {

      // Arrange — obtain a valid access_token via the authorization code flow.
      const tokens = await obtainInitialTokens(page, context);
      const accessToken = tokens.access_token as string;

      // Act — revoke the access_token (RFC 7009 §2.1).
      // The server must respond with HTTP 200 regardless of whether the token
      // was valid; RFC 7009 §2.2 requires 200 in all successful cases.
      const revokeResponse = await page.request.post(REVOKE_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });

      // Assert — RFC 7009 §2.2 requires HTTP 200 on successful revocation.
      expect(revokeResponse.status()).toBe(200);

      // Assert — introspecting the now-revoked token must return active: false
      // (RFC 7662 §2.2).  This confirms the revocation was persisted.
      const introspectResponse = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });

      expect(introspectResponse.status()).toBe(200);
      const introspectBody = await introspectResponse.json();

      // RFC 7662 §2.2: active MUST be false for a revoked token.
      expect(introspectBody.active).toBe(false);
    }
  );
});

// ---------------------------------------------------------------------------
// 2. Introspection happy path — valid access_token → active: true + 메타데이터
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/introspect — introspection happy path", () => {
  test(
    "returns active: true with scope, client_id, and exp metadata for a valid access_token",
    async ({ page, context }) => {

      // Arrange — obtain a valid access_token via the authorization code flow.
      const tokens = await obtainInitialTokens(page, context);
      const accessToken = tokens.access_token as string;

      // Decode the JWT to obtain the expected exp value for comparison.
      const { payload: jwtPayload } = decodeJwtUnsafe(accessToken);

      // Act — introspect the active access_token (RFC 7662 §2.1).
      const response = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });

      // Assert — RFC 7662 §2.2 requires HTTP 200.
      expect(response.status()).toBe(200);

      const body = await response.json();

      // active must be true for a valid, non-expired, non-revoked token.
      expect(body.active).toBe(true);

      // scope must include the originally requested scopes (RFC 7662 §2.2).
      expect(typeof body.scope).toBe("string");
      expect(body.scope).toContain("openid");
      expect(body.scope).toContain("profile");
      expect(body.scope).toContain("email");

      // client_id must match the client that requested the token.
      expect(body.client_id).toBe(VALID_CLIENT_ID);

      // exp must be a future Unix timestamp matching the JWT exp claim.
      const nowSeconds = Math.floor(Date.now() / 1000);
      expect(typeof body.exp).toBe("number");
      expect(body.exp).toBeGreaterThan(nowSeconds);
      expect(body.exp).toBe(jwtPayload.exp);

      // sub must be present and non-empty (the authenticated user's subject).
      expect(typeof body.sub).toBe("string");
      expect((body.sub as string).length).toBeGreaterThan(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 3. Introspect revoked token — 폐기된 토큰 → active: false
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/introspect — revoked token", () => {
  test(
    "returns active: false when introspecting a previously revoked access_token",
    async ({ page, context }) => {

      // Arrange — obtain a valid access_token via the authorization code flow.
      const tokens = await obtainInitialTokens(page, context);
      const accessToken = tokens.access_token as string;

      // Arrange — revoke the access_token first (RFC 7009 §2.1).
      const revokeResponse = await page.request.post(REVOKE_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(revokeResponse.status()).toBe(200);

      // Act — introspect the revoked token (RFC 7662 §2.1).
      const response = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });

      // Assert — RFC 7662 §2.2 requires HTTP 200 with active: false for a
      // revoked token.  The server must NOT return 401/403 in this case.
      expect(response.status()).toBe(200);

      const body = await response.json();

      // active MUST be false for a revoked token (RFC 7662 §2.2).
      expect(body.active).toBe(false);
    }
  );
});

// ---------------------------------------------------------------------------
// 4. Unknown vs Blacklisted — 존재하지 않는 토큰 vs 블랙리스트 토큰 구분
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/introspect — unknown vs blacklisted token", () => {
  test(
    "unknown token (never issued, not in revoked_tokens) returns active: false with no metadata",
    async ({ page }) => {

      // Arrange — a completely fabricated token that was never issued by the
      // server.  It has no corresponding record in the tokens table and no
      // entry in the revoked_tokens blacklist table.
      const unknownToken = "unknown-token-never-issued-" + Date.now();

      // Act — introspect the unknown token.
      const response = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: unknownToken,
        }).toString(),
      });

      // Assert — RFC 7662 §2.2: unknown tokens must return 200 with active: false.
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body.active).toBe(false);

      // Assert — no metadata fields should be present for an unknown token.
      // The server must not leak information about token validity.
      expect(body.scope).toBeUndefined();
      expect(body.client_id).toBeUndefined();
      expect(body.sub).toBeUndefined();
      expect(body.exp).toBeUndefined();
    }
  );

  test(
    "blacklisted token (jti in revoked_tokens) transitions from active: true → false, double-revoke is idempotent",
    async ({ page, context }) => {

      // Arrange — obtain a valid access_token via the full authorization code flow.
      const tokens = await obtainInitialTokens(page, context);
      const accessToken = tokens.access_token as string;

      // Step 1: verify the token is currently active with full metadata.
      const priorResponse = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
        }).toString(),
      });
      expect(priorResponse.status()).toBe(200);
      const priorBody = await priorResponse.json();

      // Baseline — the token MUST be active with metadata before revocation.
      // This proves the subsequent active: false is caused by blacklisting,
      // not by the token never having existed.
      expect(priorBody.active).toBe(true);
      expect(priorBody.client_id).toBe(VALID_CLIENT_ID);
      expect(typeof priorBody.scope).toBe("string");
      expect(typeof priorBody.sub).toBe("string");
      expect(typeof priorBody.exp).toBe("number");

      // Step 2: first revoke — stores jti in revoked_tokens (INSERT).
      const revokeResponse1 = await page.request.post(REVOKE_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(revokeResponse1.status()).toBe(200);

      // Step 3: introspect the now-blacklisted token.
      const afterResponse = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
        }).toString(),
      });
      expect(afterResponse.status()).toBe(200);
      const afterBody = await afterResponse.json();

      // The token must now be inactive, but — unlike an unknown token —
      // metadata is still returned because the jti exists in the blacklist
      // and the token record is preserved in the tokens table.
      expect(afterBody.active).toBe(false);
      expect(afterBody.client_id).toBe(VALID_CLIENT_ID);
      expect(typeof afterBody.scope).toBe("string");
      expect(afterBody.scope).toContain("openid");
      expect(typeof afterBody.sub).toBe("string");
      expect(typeof afterBody.exp).toBe("number");

      // Step 4: double-revoke — the jti already exists in revoked_tokens,
      // so INSERT OR IGNORE must keep it idempotent (no error, still 200).
      // This is the key behavioral difference from an unknown token:
      // an unknown token has nothing in revoked_tokens, but a blacklisted
      // token's jti persists across repeated revoke calls.
      const revokeResponse2 = await page.request.post(REVOKE_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(revokeResponse2.status()).toBe(200);

      // After double-revoke, introspection must still return active: false.
      const finalResponse = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
        }).toString(),
      });
      expect(finalResponse.status()).toBe(200);
      const finalBody = await finalResponse.json();
      expect(finalBody.active).toBe(false);
    }
  );
});

// ---------------------------------------------------------------------------
// 5. Introspect expired token — 만료된 access_token → active: false
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/introspect — expired token", () => {
  test(
    "returns active: false when introspecting an expired access_token",
    async ({ page }) => {

      // Arrange — use a fabricated JWT-shaped token string whose exp claim is
      // set to a Unix timestamp in the past (2020-01-01T00:00:00Z = 1577836800).
      // When activating this test, replace this stub with a token obtained from
      // the server with a short ACCESS_TOKEN_LIFESPAN and then waited for expiry:
      //
      //   const tokens = await obtainInitialTokens(page, context);
      //   await page.waitForTimeout(ACCESS_TOKEN_LIFESPAN_MS + 500);
      //   const accessToken = tokens.access_token as string;
      //
      // The stub value below is intentionally not a real JWT so that the server
      // rejects it as expired/invalid and returns active: false without any
      // risk of accidentally matching a live token in the test database.
      const expiredAccessToken =
        "expired-access-token-placeholder-dld678-not-a-real-jwt";

      // Act — introspect the expired (stub) access_token.
      const response = await page.request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: expiredAccessToken,
          token_type_hint: "access_token",
        }).toString(),
      });

      // Assert — RFC 7662 §2.2 requires HTTP 200 with active: false for an
      // expired or otherwise invalid token.  The server must NOT return an
      // error status; active: false is the correct representation of any
      // token that is no longer valid (expired, revoked, or unknown).
      expect(response.status()).toBe(200);

      const body = await response.json();

      // active MUST be false for an expired token (RFC 7662 §2.2).
      expect(body.active).toBe(false);
    }
  );
});
