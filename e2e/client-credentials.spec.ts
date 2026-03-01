import { test, expect } from "@playwright/test";

/**
 * Client Credentials Grant e2e specs.
 *
 * Covers POST /oauth2/token with grant_type=client_credentials (RFC 6749 §4.4).
 * This grant type is used for machine-to-machine authentication where no
 * end-user is involved.  A confidential client authenticates directly with
 * the token endpoint using its client_id and client_secret.
 *
 * All tests in this file are skipped (DLD-672) until the Client Credentials
 * grant factory (compose.OAuth2ClientCredentialsGrantFactory) is registered
 * and a dedicated test client is seeded.  Remove each `test.skip()` call once
 * the corresponding server-side feature is in place.
 *
 * Prerequisites (not yet satisfied — hence the skips):
 *   - compose.OAuth2ClientCredentialsGrantFactory registered in main.go
 *   - A Client Credentials client seeded when SEED_TEST_CLIENT=1:
 *       client_id:     "cc-client"
 *       client_secret: "cc-secret"
 *       grant_types:   ["client_credentials"]
 *       scopes:        ["read", "write"]
 *   - The existing "test-client" must NOT have "client_credentials" in its
 *     grant_types (used for the unauthorized_client error case).
 *
 * Parent issue: DLD-577 (MyAuth — 개인 인프라용 OAuth/OIDC Server)
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/** Confidential client dedicated to the Client Credentials grant. */
const CC_CLIENT_ID = "cc-client";
const CC_CLIENT_SECRET = "cc-secret";

/**
 * Scope requested in the Client Credentials token request.
 * The cc-client must be pre-configured to allow these scopes.
 */
const CC_SCOPE = "read write";

/**
 * Existing authorization_code client that does NOT have "client_credentials"
 * in its registered grant_types.  Used to verify unauthorized_client errors.
 */
const UNAUTHORIZED_CLIENT_ID = "test-client";
const UNAUTHORIZED_CLIENT_SECRET = "test-secret";

const TOKEN_ENDPOINT = "/oauth2/token";

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
// 1. Happy path — client credentials → access_token 수신, refresh_token 없음
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — client_credentials happy path", () => {
  test(
    "issues an access_token with token_type=Bearer and no refresh_token",
    async ({ request }) => {
      // Arrange — use the cc-client which has "client_credentials" grant allowed.

      // Act — POST to the token endpoint with grant_type=client_credentials.
      // Client authentication uses HTTP Basic Auth (client_secret_basic).
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

      // Assert — RFC 6749 §4.4.3 requires HTTP 200 with an access_token.
      expect(response.status()).toBe(200);

      const body = await response.json();

      // access_token must be present and non-empty.
      expect(typeof body.access_token).toBe("string");
      expect(body.access_token.length).toBeGreaterThan(0);

      // token_type must be "Bearer" (RFC 6749 §7.1).
      expect(body.token_type).toMatch(/^bearer$/i);

      // expires_in must be a positive integer.
      expect(typeof body.expires_in).toBe("number");
      expect(body.expires_in).toBeGreaterThan(0);

      // Client Credentials grant MUST NOT issue a refresh_token (RFC 6749 §4.4.3).
      // The field must be absent or explicitly null/undefined.
      expect(body.refresh_token).toBeUndefined();
    }
  );
});

// ---------------------------------------------------------------------------
// 2. 스코프 검증 — 발급된 access_token JWT의 scope claim 확인
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — client_credentials scope claim", () => {
  test(
    "access_token JWT contains the requested scopes in the scope claim",
    async ({ request }) => {
      // Arrange — request specific scopes from the cc-client.

      // Act
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

      // Decode the JWT access_token without signature verification.
      // (Signature verification is covered separately via JWKS.)
      const { payload } = decodeJwtUnsafe(body.access_token);

      // Assert — the scope claim must include every requested scope.
      const scopeValue = payload.scope as string;
      expect(scopeValue).toContain("read");
      expect(scopeValue).toContain("write");
    }
  );
});

// ---------------------------------------------------------------------------
// 3. 인증 실패 — 잘못된 client_secret → invalid_client 에러
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — client_credentials error: invalid_client", () => {
  test(
    "returns 401 invalid_client when client_secret is incorrect",
    async ({ request }) => {
      // Arrange — use the correct client_id but a wrong client_secret.

      // Act
      const response = await request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(CC_CLIENT_ID, "wrong-secret"),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "client_credentials",
          scope: CC_SCOPE,
        }).toString(),
      });

      // Assert — RFC 6749 §5.2 requires 401 with error=invalid_client when
      // the client authentication fails via HTTP Basic Auth.
      expect(response.status()).toBe(401);
      const body = await response.json();
      expect(body.error).toBe("invalid_client");
    }
  );
});

// ---------------------------------------------------------------------------
// 4. 권한 없음 — client_credentials grant가 허용되지 않은 클라이언트
// ---------------------------------------------------------------------------

test.describe("POST /oauth2/token — client_credentials error: unauthorized_client", () => {
  test(
    "returns 400 unauthorized_client when the client is not allowed to use client_credentials grant",
    async ({ request }) => {
      // Arrange — test-client only has "authorization_code" and "refresh_token"
      // in its registered grant_types; "client_credentials" is not included.
      // The server must reject this request even though the credentials are valid.

      // Act
      const response = await request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(
            UNAUTHORIZED_CLIENT_ID,
            UNAUTHORIZED_CLIENT_SECRET
          ),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "client_credentials",
          scope: CC_SCOPE,
        }).toString(),
      });

      // Assert — RFC 6749 §5.2 requires 400 with error=unauthorized_client when
      // the authenticated client is not authorized to use this grant type.
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("unauthorized_client");
    }
  );
});
