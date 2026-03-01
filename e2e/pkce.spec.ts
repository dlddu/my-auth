import { test, expect } from "@playwright/test";
import { createHash, randomBytes } from "crypto";

/**
 * PKCE (RFC 7636) e2e specs.
 *
 * Covers the Authorization Code flow with Proof Key for Code Exchange:
 *   - authorize 요청에 code_challenge + code_challenge_method=S256 포함
 *   - token 교환 시 올바른 code_verifier 포함 → 토큰 발급 성공
 *   - token 교환 시 code_verifier 누락 → invalid_grant 에러
 *   - token 교환 시 code_verifier 불일치 → invalid_grant 에러
 *   - public 클라이언트(client_secret 없음) PKCE 전체 플로우
 *
 * All tests in this file are skipped (DLD-670) until PKCE support is
 * implemented.  Remove each `test.skip()` call once the corresponding
 * server-side feature is in place.
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const VALID_CLIENT_ID = "test-client";
const VALID_CLIENT_SECRET = "test-secret";
const VALID_REDIRECT_URI = "http://localhost:9000/callback";
const VALID_SCOPE = "openid profile email";
const VALID_STATE = "test-state-pkce-670";
const VALID_NONCE = "test-nonce-pkce-670";

/** Public client registered without a client_secret (PKCE-only auth). */
const PUBLIC_CLIENT_ID = "public-client";

const AUTH_ENDPOINT = "/oauth2/auth";
const TOKEN_ENDPOINT = "/oauth2/token";

// ---------------------------------------------------------------------------
// Helper: PKCE code_verifier / code_challenge generation (RFC 7636 §4.1–4.2)
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically random code_verifier.
 * Length: 43 characters (base64url of 32 random bytes satisfies RFC 7636 §4.1).
 */
function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Derives the S256 code_challenge from a code_verifier.
 * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))  (RFC 7636 §4.2)
 */
function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

// ---------------------------------------------------------------------------
// Helper: obtain an authorization code via login → consent approve flow
//         with PKCE parameters included in the authorization request.
//
// Mirrors the pattern from token.spec.ts obtainAuthorizationCode() but
// adds code_challenge and code_challenge_method to the auth params.
// ---------------------------------------------------------------------------

/**
 * Performs the full login → consent-approve flow with PKCE parameters and
 * returns the authorization code extracted from the redirect Location header.
 *
 * @param page           Playwright Page object (carries browser session)
 * @param context        Playwright BrowserContext (used to read session cookies)
 * @param codeChallenge  S256 code_challenge derived from the code_verifier
 * @param nonce          OIDC nonce value to include in the authorization request
 * @param clientId       OAuth2 client_id (defaults to confidential test-client)
 * @returns authorization code string
 */
async function obtainAuthorizationCodeWithPkce(
  page: import("@playwright/test").Page,
  context: import("@playwright/test").BrowserContext,
  codeChallenge: string,
  nonce: string = VALID_NONCE,
  clientId: string = VALID_CLIENT_ID
): Promise<string> {
  // Step 1 — log in to establish a session cookie.
  await page.goto("/login");
  await page.getByLabel("Email").fill("admin@test.local");
  await page.getByLabel("Password").fill("test-password");
  await page.getByRole("button", { name: /log\s*in/i }).click();

  // Step 2 — navigate to the authorization endpoint with PKCE parameters so
  // the consent page is rendered and the server binds the code_challenge to
  // the pending authorization request.
  const authParams = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: VALID_REDIRECT_URI,
    scope: VALID_SCOPE,
    state: VALID_STATE,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  await page.goto(`${AUTH_ENDPOINT}?${authParams.toString()}`);
  await expect(
    page.getByRole("button", { name: /승인|approve/i })
  ).toBeVisible();

  // Step 3 — send the approve POST with the session cookie so the server
  // issues an authorization code bound to the code_challenge.
  const cookies = await context.cookies();
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");

  const response = await page.request.post(
    `${AUTH_ENDPOINT}?${authParams.toString()}`,
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
// 1. PKCE 파라미터 포함 authorize 요청 → consent 페이지 렌더링
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/auth — PKCE parameters", () => {
  test(
    "renders the consent page when code_challenge and code_challenge_method=S256 are included",
    async ({ page }) => {

      // Arrange — generate a fresh PKCE pair.
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      // Arrange — log in to establish a session.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      // Act — navigate to the authorization endpoint with PKCE params.
      const authParams = new URLSearchParams({
        response_type: "code",
        client_id: VALID_CLIENT_ID,
        redirect_uri: VALID_REDIRECT_URI,
        scope: VALID_SCOPE,
        state: VALID_STATE,
        nonce: VALID_NONCE,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      });
      await page.goto(`${AUTH_ENDPOINT}?${authParams.toString()}`);

      // Assert — the consent page must be rendered and the approve button
      // must be visible, confirming that the server accepted the PKCE params.
      await expect(page).toHaveURL(/\/oauth2\/auth/);
      await expect(
        page.getByRole("button", { name: /승인|approve/i })
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 2. Token 교환 시 올바른 code_verifier 포함 → 토큰 발급 성공
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — PKCE happy path", () => {
  test(
    "issues access_token, id_token, and refresh_token when a valid code_verifier is supplied",
    async ({ page, context }) => {

      // Arrange — generate a PKCE pair and obtain an authorization code.
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      const code = await obtainAuthorizationCodeWithPkce(
        page,
        context,
        codeChallenge
      );

      // Act — exchange the code for tokens, providing the matching
      // code_verifier so the server can verify the S256 challenge.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: VALID_REDIRECT_URI,
          code_verifier: codeVerifier,
        }).toString(),
      });

      // Assert — HTTP 200 with all three token types present.
      expect(response.status()).toBe(200);

      const body = await response.json();

      expect(typeof body.access_token).toBe("string");
      expect(body.access_token.length).toBeGreaterThan(0);

      expect(typeof body.id_token).toBe("string");
      expect(body.id_token.length).toBeGreaterThan(0);

      expect(typeof body.refresh_token).toBe("string");
      expect(body.refresh_token.length).toBeGreaterThan(0);

      expect(body.token_type).toMatch(/^bearer$/i);

      expect(typeof body.expires_in).toBe("number");
      expect(body.expires_in).toBeGreaterThan(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 3. Token 교환 시 code_verifier 누락 → invalid_grant 에러
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — PKCE error: code_verifier missing", () => {
  test(
    "returns 400 invalid_grant when code_verifier is omitted from the token request",
    async ({ page, context }) => {

      // Arrange — generate a PKCE pair and obtain a PKCE-bound authorization code.
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);
      const code = await obtainAuthorizationCodeWithPkce(
        page,
        context,
        codeChallenge
      );

      // Act — exchange the code without providing code_verifier.
      // RFC 7636 §4.6 requires the server to reject this with invalid_grant.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: VALID_REDIRECT_URI,
          // code_verifier intentionally omitted
        }).toString(),
      });

      // Assert — the server must reject the request because the authorization
      // code was issued with a code_challenge but no verifier was supplied.
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});

// ---------------------------------------------------------------------------
// 4. Token 교환 시 code_verifier 불일치 → invalid_grant 에러
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — PKCE error: code_verifier mismatch", () => {
  test(
    "returns 400 invalid_grant when code_verifier does not match the code_challenge",
    async ({ page, context }) => {

      // Arrange — generate a PKCE pair for the authorization request, then
      // generate a completely different verifier for the token request.
      const correctVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(correctVerifier);
      const wrongVerifier = generateCodeVerifier(); // different random value

      const code = await obtainAuthorizationCodeWithPkce(
        page,
        context,
        codeChallenge
      );

      // Act — exchange the code with the wrong code_verifier.
      // SHA256(wrongVerifier) will not equal the stored codeChallenge.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(VALID_CLIENT_ID, VALID_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: VALID_REDIRECT_URI,
          code_verifier: wrongVerifier,
        }).toString(),
      });

      // Assert — RFC 7636 §4.6: the server must reject the mismatched verifier.
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid_grant");
    }
  );
});

// ---------------------------------------------------------------------------
// 5. Public 클라이언트(client_secret 없음) PKCE 전체 플로우
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — public client PKCE flow", () => {
  test(
    "issues tokens to a public client authenticated solely via PKCE without a client_secret",
    async ({ page, context }) => {

      // Arrange — generate a PKCE pair for the public client flow.
      // Public clients (no client_secret) rely on PKCE as the sole proof of
      // possession; the server must not require client_secret_basic auth.
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      const code = await obtainAuthorizationCodeWithPkce(
        page,
        context,
        codeChallenge,
        VALID_NONCE,
        PUBLIC_CLIENT_ID
      );

      // Act — token request with only client_id in the body (no Authorization
      // header, no client_secret).  RFC 6749 §2.1 allows public clients to
      // identify themselves using client_id alone.
      const response = await page.request.post(TOKEN_ENDPOINT, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: PUBLIC_CLIENT_ID,
          code,
          redirect_uri: VALID_REDIRECT_URI,
          code_verifier: codeVerifier,
        }).toString(),
      });

      // Assert — the server must accept the request and issue tokens.
      expect(response.status()).toBe(200);

      const body = await response.json();

      expect(typeof body.access_token).toBe("string");
      expect(body.access_token.length).toBeGreaterThan(0);

      expect(typeof body.id_token).toBe("string");
      expect(body.id_token.length).toBeGreaterThan(0);

      expect(body.token_type).toMatch(/^bearer$/i);

      expect(typeof body.expires_in).toBe("number");
      expect(body.expires_in).toBeGreaterThan(0);
    }
  );
});
