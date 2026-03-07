import { test, expect } from "@playwright/test";

/**
 * Admin Sessions and Tokens management e2e specs.
 *
 * All tests in this file are skipped (DLD-684) until the Admin session/token management
 * endpoints are implemented.
 * Remove each `test.skip()` call once the corresponding server-side feature is in place.
 *
 * Prerequisites (not yet satisfied — hence the skips):
 *   - GET    /api/admin/sessions         endpoint registered
 *   - DELETE /api/admin/sessions/:id     endpoint registered
 *   - GET    /api/admin/tokens           endpoint registered
 *   - DELETE /api/admin/tokens/:id       endpoint registered
 *   - DELETE /api/admin/sessions         bulk revocation endpoint registered
 *   - DELETE /api/admin/tokens           bulk revocation endpoint registered
 *   - Admin Bearer token authentication middleware covers sessions/tokens routes
 *
 * Parent issue: DLD-577 (MyAuth — 개인 인프라용 OAuth/OIDC Server)
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/** Base paths for Admin session and token management endpoints. */
const ADMIN_SESSIONS_ENDPOINT = "/api/admin/sessions";
const ADMIN_TOKENS_ENDPOINT = "/api/admin/tokens";

/** OAuth2 endpoints used to set up pre-existing sessions and tokens. */
const TOKEN_ENDPOINT = "/oauth2/token";
const INTROSPECT_ENDPOINT = "/oauth2/introspect";

/**
 * Placeholder admin Bearer token.
 * Replace with a real token value once the Admin auth mechanism covers
 * sessions/tokens routes.  Mirrors the value used in admin-clients.spec.ts.
 */
const ADMIN_BEARER_TOKEN = "admin-bearer-token-placeholder-dld682";

/**
 * Pre-seeded OAuth2 client used to create sessions and tokens for test setup.
 * This client must have the authorization_code grant type registered.
 */
const VALID_CLIENT_ID = "test-client";
const VALID_CLIENT_SECRET = "test-secret";
const VALID_REDIRECT_URI = "http://localhost:9000/callback";
const VALID_SCOPE = "openid profile email";

/**
 * Pre-seeded Client Credentials client used to create tokens without a
 * user session.  Must have grant_types=["client_credentials"].
 */
const CC_CLIENT_ID = "cc-client";
const CC_CLIENT_SECRET = "cc-secret";
const CC_SCOPE = "read write";

// ---------------------------------------------------------------------------
// Helper: build the Authorization header for Admin API requests.
// ---------------------------------------------------------------------------

function adminAuthHeader(): string {
  return `Bearer ${ADMIN_BEARER_TOKEN}`;
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
// Helper: obtain an access_token via client_credentials grant.
// Used to pre-populate the tokens table so that list/delete tests have data.
// ---------------------------------------------------------------------------

async function obtainClientCredentialsToken(
  request: import("@playwright/test").APIRequestContext
): Promise<string> {
  const response = await request.post(TOKEN_ENDPOINT, {
    headers: {
      Authorization: basicAuthHeader(CC_CLIENT_ID, CC_CLIENT_SECRET),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    data: new URLSearchParams({
      grant_type: "client_credentials",
      scope: CC_SCOPE,
    }).toString(),
  });

  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(typeof body.access_token).toBe("string");
  return body.access_token as string;
}

// ---------------------------------------------------------------------------
// Helper: perform login → consent approve flow and return an authorization code.
// Requires the { page, context } fixture because session cookies must persist.
// ---------------------------------------------------------------------------

async function obtainAuthorizationCode(
  page: import("@playwright/test").Page,
  context: import("@playwright/test").BrowserContext,
  nonce: string = "test-nonce-dld684"
): Promise<string> {
  // Step 1 — establish a browser session via the login page.
  await page.goto("/login");
  await page.getByLabel("Email").fill("admin@test.local");
  await page.getByLabel("Password").fill("test-password");
  await page.getByRole("button", { name: /log\s*in/i }).click();

  // Step 2 — navigate to the authorization endpoint to render the consent page.
  const authParams = new URLSearchParams({
    response_type: "code",
    client_id: VALID_CLIENT_ID,
    redirect_uri: VALID_REDIRECT_URI,
    scope: VALID_SCOPE,
    state: "test-state-dld684",
    nonce,
  });
  await page.goto(`/oauth2/auth?${authParams.toString()}`);
  await expect(
    page.getByRole("button", { name: /승인|approve/i })
  ).toBeVisible();

  // Step 3 — POST the consent approval with session cookies to obtain the code.
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
// Helper: complete the authorization code flow and return the token response.
// Returns an object containing access_token, id_token, and refresh_token.
// ---------------------------------------------------------------------------

async function obtainTokensViaAuthCode(
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
  expect(typeof body.access_token).toBe("string");
  return body as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 1. GET /api/admin/sessions — 활성 세션 목록 조회 (happy path)
//    세션 목록이 배열로 반환되며 각 항목에 필수 필드 포함 검증
// ---------------------------------------------------------------------------

test.describe("GET /api/admin/sessions — list active sessions happy path", () => {
  test(
    "returns a JSON array of active sessions with id, client_id, subject, scopes, and expires_at",
    async ({ request }) => {
      // Arrange — no additional setup required; the seeded test data provides
      // at least the sessions created by the server's own seed step.

      // Act — GET the active sessions list with a valid Admin Bearer token.
      const response = await request.get(ADMIN_SESSIONS_ENDPOINT, {
        headers: {
          Authorization: adminAuthHeader(),
        },
      });

      // Assert — HTTP 200 with a JSON array.
      expect(response.status()).toBe(200);

      const body = await response.json();
      expect(Array.isArray(body)).toBe(true);

      // Assert — each session entry must contain the required fields derived
      // from the sessions table schema:
      //   id, client_id, subject, scopes, expires_at, created_at
      for (const session of body as Record<string, unknown>[]) {
        expect(typeof session.id).toBe("string");
        expect((session.id as string).length).toBeGreaterThan(0);

        expect(typeof session.client_id).toBe("string");
        expect((session.client_id as string).length).toBeGreaterThan(0);

        expect(typeof session.subject).toBe("string");

        // expires_at must be a parseable date/time string or Unix timestamp.
        expect(session.expires_at).toBeDefined();
      }
    }
  );
});

// ---------------------------------------------------------------------------
// 2. GET /api/admin/sessions — 인증 없이 요청 → 401
// ---------------------------------------------------------------------------

test.describe("GET /api/admin/sessions — error: missing admin token", () => {
  test(
    "returns 401 when the Authorization header is absent",
    async ({ request }) => {
      // Act — GET without an Authorization header.
      const response = await request.get(ADMIN_SESSIONS_ENDPOINT);

      // Assert — the server must reject unauthenticated requests with 401.
      expect(response.status()).toBe(401);
    }
  );
});

// ---------------------------------------------------------------------------
// 3. DELETE /api/admin/sessions/:id — 세션 폐기 happy path
//    폐기 후 해당 세션 ID로 발급된 access_token이 무효화됨을 검증
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/sessions/:id — revoke session happy path", () => {
  test(
    "revokes the session and the associated access_token becomes inactive on introspection",
    async ({ page, context, request }) => {
      // Arrange — obtain an access_token via the authorization code flow.
      // This creates an active session in the sessions table.
      const tokens = await obtainTokensViaAuthCode(page, context);
      const accessToken = tokens.access_token as string;

      // Sanity check — the token must be active before the session is revoked.
      const introspectBefore = await request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(introspectBefore.status()).toBe(200);
      const beforeBody = await introspectBefore.json();
      expect(beforeBody.active).toBe(true);

      // Arrange — list sessions to obtain the session id for this access_token.
      const listResponse = await request.get(ADMIN_SESSIONS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });
      expect(listResponse.status()).toBe(200);

      const sessions = await listResponse.json() as Record<string, unknown>[];
      // Find the session whose client_id matches VALID_CLIENT_ID.
      const targetSession = sessions.find(
        (s) => s.client_id === VALID_CLIENT_ID
      );
      expect(targetSession).toBeDefined();
      const sessionId = targetSession!.id as string;

      // Act — DELETE /api/admin/sessions/:id to revoke the session.
      const deleteResponse = await request.delete(
        `${ADMIN_SESSIONS_ENDPOINT}/${sessionId}`,
        {
          headers: { Authorization: adminAuthHeader() },
        }
      );

      // Assert — the server must respond with 204 No Content on success.
      expect(deleteResponse.status()).toBe(204);

      // Assert — introspecting the access_token associated with the revoked
      // session must now return active: false because the session is gone.
      const introspectAfter = await request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(introspectAfter.status()).toBe(200);
      const afterBody = await introspectAfter.json();

      // The access_token must be inactive once its parent session is revoked.
      expect(afterBody.active).toBe(false);
    }
  );
});

// ---------------------------------------------------------------------------
// 4. DELETE /api/admin/sessions/:id — 존재하지 않는 세션 폐기 → 404
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/sessions/:id — error: not found", () => {
  test(
    "returns 404 when the requested session id does not exist",
    async ({ request }) => {
      // Arrange — a session id that was never created.
      const nonExistentId = "session-does-not-exist-dld684-" + Date.now();

      // Act — DELETE /api/admin/sessions/:id for the non-existent session.
      const response = await request.delete(
        `${ADMIN_SESSIONS_ENDPOINT}/${nonExistentId}`,
        {
          headers: { Authorization: adminAuthHeader() },
        }
      );

      // Assert — the server must respond with 404 Not Found.
      expect(response.status()).toBe(404);
    }
  );
});

// ---------------------------------------------------------------------------
// 5. GET /api/admin/tokens — 활성 토큰 목록 조회 (happy path)
//    토큰 목록이 배열로 반환되며 타입·클라이언트·scope·만료 필드 포함 검증
// ---------------------------------------------------------------------------

test.describe("GET /api/admin/tokens — list active tokens happy path", () => {
  test(
    "returns a JSON array of tokens with signature, client_id, subject, scopes, and expires_at",
    async ({ request }) => {
      // Arrange — issue a client_credentials access_token so the tokens table
      // has at least one entry when the list is fetched.
      await obtainClientCredentialsToken(request);

      // Act — GET the active token list with a valid Admin Bearer token.
      const response = await request.get(ADMIN_TOKENS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });

      // Assert — HTTP 200 with a JSON array.
      expect(response.status()).toBe(200);

      const body = await response.json();
      expect(Array.isArray(body)).toBe(true);
      expect((body as unknown[]).length).toBeGreaterThan(0);

      // Assert — each token entry must contain the required fields derived
      // from the tokens table schema:
      //   signature (or id), client_id, subject, scopes, expires_at, created_at
      for (const token of body as Record<string, unknown>[]) {
        // The token identifier may be exposed as "id" or "signature".
        const hasId =
          typeof token.id === "string" ||
          typeof token.signature === "string";
        expect(hasId).toBe(true);

        expect(typeof token.client_id).toBe("string");
        expect((token.client_id as string).length).toBeGreaterThan(0);

        // scopes must be present (array or space-separated string).
        expect(token.scopes ?? token.scope).toBeDefined();

        // expires_at must be defined.
        expect(token.expires_at).toBeDefined();
      }
    }
  );
});

// ---------------------------------------------------------------------------
// 6. GET /api/admin/tokens — 인증 없이 요청 → 401
// ---------------------------------------------------------------------------

test.describe("GET /api/admin/tokens — error: missing admin token", () => {
  test(
    "returns 401 when the Authorization header is absent",
    async ({ request }) => {
      // Act — GET without an Authorization header.
      const response = await request.get(ADMIN_TOKENS_ENDPOINT);

      // Assert — unauthenticated requests must be rejected with 401.
      expect(response.status()).toBe(401);
    }
  );
});

// ---------------------------------------------------------------------------
// 7. DELETE /api/admin/tokens/:id — 토큰 폐기 happy path
//    폐기 후 introspect가 active: false를 반환하는지 검증
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/tokens/:id — revoke token happy path", () => {
  test(
    "revokes the token and subsequent introspection returns active: false",
    async ({ request }) => {
      // Arrange — obtain a client_credentials access_token.
      // client_credentials tokens are self-contained and do not require a
      // browser session, making this test runnable with the { request } fixture.
      const accessToken = await obtainClientCredentialsToken(request);

      // Sanity check — verify the token is active before revocation.
      const introspectBefore = await request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(CC_CLIENT_ID, CC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(introspectBefore.status()).toBe(200);
      const beforeBody = await introspectBefore.json();
      expect(beforeBody.active).toBe(true);

      // Arrange — list tokens to find the token id/signature for the
      // newly issued access_token.
      const listResponse = await request.get(ADMIN_TOKENS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });
      expect(listResponse.status()).toBe(200);

      const tokens = await listResponse.json() as Record<string, unknown>[];
      // Find the token that belongs to CC_CLIENT_ID.
      const targetToken = tokens.find(
        (t) => t.client_id === CC_CLIENT_ID
      );
      expect(targetToken).toBeDefined();

      // The token identifier may be "id" or "signature" depending on the API.
      const tokenId = (targetToken!.id ?? targetToken!.signature) as string;
      expect(typeof tokenId).toBe("string");

      // Act — DELETE /api/admin/tokens/:id to revoke the token.
      const deleteResponse = await request.delete(
        `${ADMIN_TOKENS_ENDPOINT}/${tokenId}`,
        {
          headers: { Authorization: adminAuthHeader() },
        }
      );

      // Assert — the server must respond with 204 No Content on success.
      expect(deleteResponse.status()).toBe(204);

      // Assert — the token must now be inactive when introspected.
      const introspectAfter = await request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(CC_CLIENT_ID, CC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(introspectAfter.status()).toBe(200);
      const afterBody = await introspectAfter.json();

      // active MUST be false after the token has been revoked via the Admin API.
      expect(afterBody.active).toBe(false);
    }
  );
});

// ---------------------------------------------------------------------------
// 8. DELETE /api/admin/tokens/:id — 존재하지 않는 토큰 폐기 → 404
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/tokens/:id — error: not found", () => {
  test(
    "returns 404 when the requested token id does not exist",
    async ({ request }) => {
      // Arrange — a token identifier that was never issued.
      const nonExistentId = "token-does-not-exist-dld684-" + Date.now();

      // Act — DELETE /api/admin/tokens/:id for the non-existent token.
      const response = await request.delete(
        `${ADMIN_TOKENS_ENDPOINT}/${nonExistentId}`,
        {
          headers: { Authorization: adminAuthHeader() },
        }
      );

      // Assert — the server must respond with 404 Not Found.
      expect(response.status()).toBe(404);
    }
  );
});

// ---------------------------------------------------------------------------
// 9. DELETE /api/admin/sessions — 전체 세션 일괄 폐기 (bulk revocation)
//    폐기 후 세션 목록이 비어 있음을 검증
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/sessions — bulk revoke all sessions", () => {
  test(
    "revokes all active sessions and the sessions list becomes empty afterwards",
    async ({ page, context, request }) => {
      // Arrange — create at least one active session by completing an auth code flow.
      await obtainTokensViaAuthCode(page, context);

      // Sanity check — at least one session must exist before bulk revocation.
      const listBefore = await request.get(ADMIN_SESSIONS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });
      expect(listBefore.status()).toBe(200);
      const sessionsBefore = await listBefore.json() as unknown[];
      expect(sessionsBefore.length).toBeGreaterThan(0);

      // Act — DELETE /api/admin/sessions (no :id) to bulk-revoke all sessions.
      const deleteResponse = await request.delete(ADMIN_SESSIONS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });

      // Assert — the server must respond with 204 No Content.
      expect(deleteResponse.status()).toBe(204);

      // Assert — the sessions list must be empty after bulk revocation.
      const listAfter = await request.get(ADMIN_SESSIONS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });
      expect(listAfter.status()).toBe(200);
      const sessionsAfter = await listAfter.json() as unknown[];
      expect(sessionsAfter.length).toBe(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 10. DELETE /api/admin/tokens — 전체 토큰 일괄 폐기 (bulk revocation)
//     폐기 후 토큰 목록이 비어 있고 기존 토큰이 무효화됨을 검증
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/tokens — bulk revoke all tokens", () => {
  test(
    "revokes all active tokens, the tokens list becomes empty, and a previously-active token is now inactive",
    async ({ request }) => {
      // Arrange — issue a client_credentials token so the tokens table is
      // non-empty, and keep the raw access_token string for later introspection.
      const accessToken = await obtainClientCredentialsToken(request);

      // Sanity check — at least one token must exist before bulk revocation.
      const listBefore = await request.get(ADMIN_TOKENS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });
      expect(listBefore.status()).toBe(200);
      const tokensBefore = await listBefore.json() as unknown[];
      expect(tokensBefore.length).toBeGreaterThan(0);

      // Sanity check — the newly issued token must be active.
      const introspectBefore = await request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(CC_CLIENT_ID, CC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(introspectBefore.status()).toBe(200);
      expect((await introspectBefore.json()).active).toBe(true);

      // Act — DELETE /api/admin/tokens (no :id) to bulk-revoke all tokens.
      const deleteResponse = await request.delete(ADMIN_TOKENS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });

      // Assert — the server must respond with 204 No Content.
      expect(deleteResponse.status()).toBe(204);

      // Assert — the tokens list must be empty after bulk revocation.
      const listAfter = await request.get(ADMIN_TOKENS_ENDPOINT, {
        headers: { Authorization: adminAuthHeader() },
      });
      expect(listAfter.status()).toBe(200);
      const tokensAfter = await listAfter.json() as unknown[];
      expect(tokensAfter.length).toBe(0);

      // Assert — the previously-active token must now be inactive.
      const introspectAfter = await request.post(INTROSPECT_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(CC_CLIENT_ID, CC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          token: accessToken,
          token_type_hint: "access_token",
        }).toString(),
      });
      expect(introspectAfter.status()).toBe(200);
      expect((await introspectAfter.json()).active).toBe(false);
    }
  );
});
