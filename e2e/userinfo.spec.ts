import { test, expect } from "@playwright/test";

/**
 * UserInfo Endpoint e2e specs.
 *
 * Covers GET /oauth2/userinfo (OIDC Core 1.0, Section 5.3).
 * Tests UserInfo claim retrieval via Bearer access_token obtained through
 * the Authorization Code flow.
 *
 * Prerequisites:
 *   - GET /oauth2/userinfo endpoint registered (custom handler using fosite IntrospectToken)
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
const VALID_STATE = "test-state-userinfo-680";
const VALID_NONCE = "test-nonce-userinfo-680";

const TOKEN_ENDPOINT = "/oauth2/token";
const USERINFO_ENDPOINT = "/oauth2/userinfo";

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
 * @param scope   OAuth 2.0 scope string (defaults to "openid profile email")
 * @returns authorization code string
 */
async function obtainAuthorizationCode(
  page: import("@playwright/test").Page,
  context: import("@playwright/test").BrowserContext,
  nonce: string = VALID_NONCE,
  scope: string = VALID_SCOPE
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
    scope,
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
// Helper: perform the full authorization code flow and exchange it for tokens,
// returning the initial token response body including access_token and id_token.
//
// scope 파라미터를 통해 테스트별로 다른 scope를 요청할 수 있습니다.
// ---------------------------------------------------------------------------

/**
 * Completes the authorization code flow and returns the token response body.
 * The returned object contains access_token, id_token, and (if granted) refresh_token.
 *
 * @param page    Playwright Page object (carries browser session)
 * @param context Playwright BrowserContext (used to read session cookies)
 * @param scope   OAuth 2.0 scope string (defaults to "openid profile email")
 * @returns parsed token endpoint response body
 */
async function obtainInitialTokens(
  page: import("@playwright/test").Page,
  context: import("@playwright/test").BrowserContext,
  scope: string = VALID_SCOPE
): Promise<Record<string, unknown>> {
  const code = await obtainAuthorizationCode(page, context, VALID_NONCE, scope);

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
  expect((body.access_token as string).length).toBeGreaterThan(0);

  return body as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 1. Happy path — scope=openid profile email → 전체 클레임 반환
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/userinfo — happy path (full scopes)", () => {
  test(
    "returns 200 with sub, name, and email claims when scope=openid profile email",
    async ({ page, context }) => {
      // Arrange — obtain tokens via the full authorization code flow with all scopes.
      const tokens = await obtainInitialTokens(page, context, VALID_SCOPE);
      const accessToken = tokens.access_token as string;
      const idTokenPayload = decodeJwtUnsafe(tokens.id_token as string).payload;

      // Act — call the UserInfo endpoint with a Bearer access_token.
      const response = await page.request.get(USERINFO_ENDPOINT, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      // Assert — HTTP 200 OK with JSON content type.
      expect(response.status()).toBe(200);
      const contentType = response.headers()["content-type"];
      expect(contentType).toContain("application/json");

      const body = await response.json();

      // sub claim — must be a non-empty string (OIDC Core §5.3).
      expect(typeof body.sub).toBe("string");
      expect((body.sub as string).length).toBeGreaterThan(0);

      // sub must match the sub claim in the id_token (OIDC Core §5.3.2).
      expect(body.sub).toBe(idTokenPayload.sub);

      // profile scope — at least one of name, given_name, or family_name must
      // be present (OIDC Core §5.1 profile scope claims).
      const hasProfileClaim =
        typeof body.name === "string" ||
        typeof body.given_name === "string" ||
        typeof body.family_name === "string";
      expect(hasProfileClaim).toBe(true);

      // email scope — email claim must be present (OIDC Core §5.1 email scope).
      expect(typeof body.email).toBe("string");
      expect((body.email as string).length).toBeGreaterThan(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 2. scope=openid のみ → sub claim만 반환, profile/email 클레임 없음
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/userinfo — scope=openid only", () => {
  test(
    "returns only sub claim and no profile/email claims when scope=openid",
    async ({ page, context }) => {
      // Arrange — obtain tokens using the minimal openid scope only.
      const tokens = await obtainInitialTokens(page, context, "openid");
      const accessToken = tokens.access_token as string;

      // Act — call the UserInfo endpoint with the openid-only access_token.
      const response = await page.request.get(USERINFO_ENDPOINT, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      // Assert — HTTP 200 OK.
      expect(response.status()).toBe(200);

      const body = await response.json();

      // sub claim — must be present (always required per OIDC Core §5.3).
      expect(typeof body.sub).toBe("string");
      expect((body.sub as string).length).toBeGreaterThan(0);

      // profile scope claims — must NOT be returned when the scope was not granted.
      // OIDC Core §5.4: claims outside the requested scope must be omitted.
      expect(body.name).toBeUndefined();
      expect(body.given_name).toBeUndefined();
      expect(body.family_name).toBeUndefined();
      expect(body.nickname).toBeUndefined();

      // email scope claims — must NOT be returned when the scope was not granted.
      expect(body.email).toBeUndefined();
      expect(body.email_verified).toBeUndefined();
    }
  );
});

// ---------------------------------------------------------------------------
// 3. 유효하지 않은 토큰 → HTTP 401 Unauthorized (RFC 6750)
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/userinfo — error: invalid token", () => {
  test(
    "returns 401 with WWW-Authenticate: Bearer header for a forged access_token",
    async ({ page }) => {
      // Arrange — use a completely fabricated token that was never issued.
      const forgedToken =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.invalidsignature";

      // Act — call the UserInfo endpoint with the forged Bearer token.
      const response = await page.request.get(USERINFO_ENDPOINT, {
        headers: {
          Authorization: `Bearer ${forgedToken}`,
        },
      });

      // Assert — RFC 6750 §3.1 requires HTTP 401 for an invalid token.
      expect(response.status()).toBe(401);

      // WWW-Authenticate header must be present and indicate the Bearer scheme
      // (RFC 6750 §3 "The WWW-Authenticate Response Header Field").
      const wwwAuthenticate = response.headers()["www-authenticate"] ?? "";
      expect(wwwAuthenticate).toMatch(/^Bearer/i);
    }
  );
});
