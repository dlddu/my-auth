import { test, expect } from "@playwright/test";

/**
 * Device Code Grant (RFC 8628) e2e specs.
 *
 * Covers the full Device Authorization Grant flow for input-constrained
 * devices (e.g. TVs, IoT devices) that cannot display a browser or accept
 * keyboard input directly:
 *   1. Device requests a device_code and user_code from the authorization server
 *   2. User visits the verification URI and enters the user_code on a companion
 *      device (browser)
 *   3. Device polls the token endpoint until the user approves or the code expires
 *
 * All tests in this file are skipped (DLD-674) until the Device Code grant
 * factory is registered and a dedicated test client is seeded.
 * Remove each `test.skip()` call once the corresponding server-side feature
 * is in place.
 *
 * Prerequisites (not yet satisfied — hence the skips):
 *   - Device Code grant factory registered in main.go
 *   - A Device Code client seeded when SEED_TEST_CLIENT=1:
 *       client_id:     "dc-client"
 *       client_secret: "dc-secret"
 *       grant_types:   ["urn:ietf:params:oauth:grant-type:device_code"]
 *       scopes:        ["read", "write"]
 *   - Device authorization endpoint implemented: POST /oauth2/device/code
 *   - Device verification endpoint implemented: POST /oauth2/device/verify
 *   - Token endpoint polling support for grant_type=urn:ietf:params:oauth:grant-type:device_code
 *   - device_codes table seeded and managed by the authorization server
 *
 * Parent issue: DLD-577 (MyAuth — 개인 인프라용 OAuth/OIDC Server)
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/** Confidential client dedicated to the Device Code grant. */
const DC_CLIENT_ID = "dc-client";
const DC_CLIENT_SECRET = "dc-secret";

/**
 * Scopes requested in the device authorization request.
 * The dc-client must be pre-configured to allow these scopes.
 */
const DC_SCOPE = "read write";

/**
 * Device Authorization endpoint (RFC 8628 §3.1).
 * Devices POST here to receive device_code, user_code, and verification_uri.
 */
const DEVICE_CODE_ENDPOINT = "/oauth2/device/code";

/**
 * User-facing verification endpoint where a companion-device browser submits
 * the user_code to link and approve the device request.
 */
const DEVICE_VERIFY_ENDPOINT = "/oauth2/device/verify";

/**
 * Token endpoint used by the device to poll for access_token once the user
 * has approved the request (RFC 8628 §3.4).
 */
const TOKEN_ENDPOINT = "/oauth2/token";

/**
 * RFC 8628 grant type URN for the device polling token request.
 */
const DEVICE_CODE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:device_code";

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
// Helper: request a fresh device_code / user_code pair from the authorization
// server.  Used as a shared Arrange step across multiple test cases.
// ---------------------------------------------------------------------------

interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval?: number;
}

async function requestDeviceAuthorization(
  request: import("@playwright/test").APIRequestContext,
  scope: string = DC_SCOPE
): Promise<DeviceAuthorizationResponse> {
  const response = await request.post(DEVICE_CODE_ENDPOINT, {
    headers: {
      Authorization: basicAuthHeader(DC_CLIENT_ID, DC_CLIENT_SECRET),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    data: new URLSearchParams({
      client_id: DC_CLIENT_ID,
      scope,
    }).toString(),
  });

  expect(response.status()).toBe(200);
  return response.json();
}

// ---------------------------------------------------------------------------
// 1. Device Authorization Request — device_code, user_code, verification_uri,
//    expires_in 수신 (RFC 8628 §3.2)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/device/code — device authorization request", () => {
  test(
    "returns device_code, user_code, verification_uri, and expires_in",
    async ({ request }) => {

      // Arrange — use the dc-client which has the device_code grant allowed.

      // Act — POST to the device authorization endpoint (RFC 8628 §3.1).
      const response = await request.post(DEVICE_CODE_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(DC_CLIENT_ID, DC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          client_id: DC_CLIENT_ID,
          scope: DC_SCOPE,
        }).toString(),
      });

      // Assert — RFC 8628 §3.2 requires HTTP 200 with the four mandatory fields.
      expect(response.status()).toBe(200);

      const body: DeviceAuthorizationResponse = await response.json();

      // device_code must be a non-empty opaque string.
      expect(typeof body.device_code).toBe("string");
      expect(body.device_code.length).toBeGreaterThan(0);

      // user_code must be a short, human-typable string.
      expect(typeof body.user_code).toBe("string");
      expect(body.user_code.length).toBeGreaterThan(0);

      // verification_uri must be a URL the user visits on their browser.
      expect(typeof body.verification_uri).toBe("string");
      expect(body.verification_uri.length).toBeGreaterThan(0);

      // expires_in must be a positive integer (seconds until the codes expire).
      expect(typeof body.expires_in).toBe("number");
      expect(body.expires_in).toBeGreaterThan(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 2. Polling — authorization_pending エラー
//    사용자가 아직 승인하지 않은 상태에서 토큰 폴링 → authorization_pending (RFC 8628 §3.5)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — device_code polling: authorization_pending", () => {
  test(
    "returns 400 authorization_pending when the user has not yet approved the request",
    async ({ request }) => {

      // Arrange — obtain a fresh device_code / user_code pair.
      // At this point the device_code status is "pending" in the DB.
      const { device_code } = await requestDeviceAuthorization(request);

      // Act — poll the token endpoint immediately, before any user interaction.
      // RFC 8628 §3.4 requires the server to return authorization_pending while
      // the user has not yet completed verification.
      const response = await request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(DC_CLIENT_ID, DC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: DEVICE_CODE_GRANT_TYPE,
          device_code,
          client_id: DC_CLIENT_ID,
        }).toString(),
      });

      // Assert — RFC 8628 §3.5 requires HTTP 400 with error=authorization_pending.
      expect(response.status()).toBe(400);

      const body = await response.json();
      expect(body.error).toBe("authorization_pending");
    }
  );
});

// ---------------------------------------------------------------------------
// 3. User Code Verification — 사용자가 user_code를 입력하고 승인 완료
//    (RFC 8628 §3.3)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/device/verify — user code verification", () => {
  test(
    "returns 200 when a logged-in user submits a valid user_code and approves",
    async ({ page, request }) => {

      // Arrange — obtain a fresh device_code / user_code pair.
      const { user_code } = await requestDeviceAuthorization(request);

      // Arrange — log in as a user on the companion browser device so the
      // verification endpoint can bind the approval to an authenticated subject.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      // Act — POST the user_code to the device verification endpoint.
      // The session cookie from the browser login is carried by the page context.
      const response = await page.request.post(DEVICE_VERIFY_ENDPOINT, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          user_code,
          action: "approve",
        }).toString(),
      });

      // Assert — the server must accept the valid user_code and mark the
      // device_code as "approved" in the device_codes table (RFC 8628 §3.3).
      expect(response.status()).toBe(200);
    }
  );
});

// ---------------------------------------------------------------------------
// 4. Happy Path — 사용자 승인 완료 후 폴링 → access_token 수신 (RFC 8628 §3.4–3.5)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — device_code happy path", () => {
  test(
    "issues an access_token with token_type=Bearer after the user approves the device request",
    async ({ page, request }) => {

      // Arrange — obtain a fresh device_code / user_code pair from the server.
      const { device_code, user_code } =
        await requestDeviceAuthorization(request);

      // Arrange — log in as a user and approve the device request via the
      // verification endpoint, simulating the user's companion-device flow.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      const verifyResponse = await page.request.post(DEVICE_VERIFY_ENDPOINT, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          user_code,
          action: "approve",
        }).toString(),
      });
      expect(verifyResponse.status()).toBe(200);

      // Act — poll the token endpoint now that the user has approved.
      // The device_code status in the DB is now "approved", so the server
      // must issue tokens on this poll (RFC 8628 §3.4).
      const tokenResponse = await request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(DC_CLIENT_ID, DC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: DEVICE_CODE_GRANT_TYPE,
          device_code,
          client_id: DC_CLIENT_ID,
        }).toString(),
      });

      // Assert — RFC 8628 §3.5 requires HTTP 200 with an access_token once
      // the user has approved the request.
      expect(tokenResponse.status()).toBe(200);

      const body = await tokenResponse.json();

      // access_token must be present and non-empty.
      expect(typeof body.access_token).toBe("string");
      expect(body.access_token.length).toBeGreaterThan(0);

      // token_type must be "Bearer" (RFC 6749 §7.1).
      expect(body.token_type).toMatch(/^bearer$/i);

      // expires_in must be a positive integer.
      expect(typeof body.expires_in).toBe("number");
      expect(body.expires_in).toBeGreaterThan(0);

      // Decode the access_token JWT and validate the scope claim.
      const { payload } = decodeJwtUnsafe(body.access_token);
      const scopeValue = payload.scope as string;
      expect(scopeValue).toContain("read");
      expect(scopeValue).toContain("write");
    }
  );
});

// ---------------------------------------------------------------------------
// 5. Error — expired_token
//    만료된 device_code로 폴링 → expired_token 에러 (RFC 8628 §3.5)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — device_code error: expired_token", () => {
  test(
    "returns 400 expired_token when polling with an expired device_code",
    async ({ request }) => {

      // Arrange — use a device_code that has already passed its expires_at
      // timestamp.  In a real test run this is achieved by either:
      //   a) Configuring the server with a very short device code lifespan
      //      (e.g. 1 s) and waiting: await new Promise(r => setTimeout(r, 2000))
      //   b) Inserting a pre-expired row directly via a test helper API.
      //
      // For the skip-state spec we use a hard-coded fake device_code value
      // that the server will look up and reject as expired.
      // When activating, replace this with a real short-lived device_code:
      //   const { device_code } = await requestDeviceAuthorization(request);
      //   await new Promise(r => setTimeout(r, 2000)); // wait for expiry
      const expiredDeviceCode = "expired-device-code-placeholder-dld674";

      // Act — poll the token endpoint with the expired device_code.
      const response = await request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(DC_CLIENT_ID, DC_CLIENT_SECRET),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: DEVICE_CODE_GRANT_TYPE,
          device_code: expiredDeviceCode,
          client_id: DC_CLIENT_ID,
        }).toString(),
      });

      // Assert — RFC 8628 §3.5 requires HTTP 400 with error=expired_token when
      // the device_code's expires_at has passed.
      expect(response.status()).toBe(400);

      const body = await response.json();
      expect(body.error).toBe("expired_token");
    }
  );
});

// ---------------------------------------------------------------------------
// 6. Error — invalid user_code
//    잘못된 user_code 입력 → 에러 응답 (RFC 8628 §3.3)
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/device/verify — error: invalid user_code", () => {
  test(
    "returns an error when the submitted user_code does not match any pending device request",
    async ({ page }) => {

      // Arrange — log in so the verification endpoint can authenticate the user.
      await page.goto("/login");
      await page.getByLabel("Email").fill("admin@test.local");
      await page.getByLabel("Password").fill("test-password");
      await page.getByRole("button", { name: /log\s*in/i }).click();

      // Act — submit a user_code that was never issued by the server.
      // RFC 8628 §3.3 requires the server to reject unknown or already-used
      // user_codes with an appropriate error response.
      const response = await page.request.post(DEVICE_VERIFY_ENDPOINT, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          user_code: "INVALID-CODE-0000",
          action: "approve",
        }).toString(),
      });

      // Assert — the server must respond with a 4xx status and an error
      // indicating the user_code is unknown or invalid.
      expect(response.status()).toBeGreaterThanOrEqual(400);
      expect(response.status()).toBeLessThan(500);

      const body = await response.json();
      // The error field must be present; acceptable values include
      // "invalid_grant", "invalid_request", or a server-specific code.
      expect(typeof body.error).toBe("string");
      expect(body.error.length).toBeGreaterThan(0);
    }
  );
});
