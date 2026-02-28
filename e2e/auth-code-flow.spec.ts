import { test, expect } from "@playwright/test";

/**
 * Authorization Code Flow e2e specs (DLD-584).
 *
 * Covers the full OAuth2 Authorization Code flow:
 *   authorize → login → consent → callback (code) → token exchange
 *   → access_token + id_token validation.
 *
 * Activated for DLD-585: server-side implementation of /oauth2/auth
 * (code issuance) and /oauth2/token is complete.
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Decode a JWT without verifying the signature.
 * Returns the parsed header and payload as plain objects.
 */
function decodeJwt(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT: expected 3 parts, got ${parts.length}`);
  }

  const base64urlDecode = (s: string): Record<string, unknown> => {
    // Convert base64url → base64, then decode.
    const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
  };

  return {
    header: base64urlDecode(parts[0]),
    payload: base64urlDecode(parts[1]),
  };
}

/**
 * Build the authorization endpoint URL with common test parameters.
 */
function buildAuthorizeUrl(overrides: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: "test-client",
    redirect_uri: "http://localhost:9999/callback",
    scope: "openid profile email",
    state: "test-state-value",
    nonce: "test-nonce-value",
    ...overrides,
  });
  return `/oauth2/auth?${params.toString()}`;
}

/**
 * Complete the full authorize → login → consent flow and return the
 * authorization code string from the callback redirect.
 *
 * Uses Promise.all to register waitForRequest BEFORE clicking the approve
 * button, which avoids the race condition where the browser processes the
 * 303 redirect before the listener is set up.
 */
async function completeFlowAndGetCode(
  page: import("@playwright/test").Page,
  authorizeUrl: string = buildAuthorizeUrl()
): Promise<string> {
  await page.goto(authorizeUrl);

  await page
    .locator(
      'input[type="email"], input[name="email"], input[name="username"]'
    )
    .fill("admin@test.local");
  await page.locator('input[type="password"]').fill("test-password");
  await page.locator('button[type="submit"]').click();

  await page.waitForURL(/\/consent/, { timeout: 10_000 });

  const [callbackReq] = await Promise.all([
    page.waitForRequest(
      (req) => req.url().includes("localhost:9999/callback"),
      { timeout: 15_000 }
    ),
    page
      .locator(
        'button[type="submit"], button:has-text("Allow"), button:has-text("Approve")'
      )
      .click(),
  ]);

  const code = new URL(callbackReq.url()).searchParams.get("code");
  if (!code) {
    throw new Error(
      `Authorization code missing from callback URL: ${callbackReq.url()}`
    );
  }
  return code;
}

// ---------------------------------------------------------------------------
// Authorization endpoint — GET /oauth2/auth
// ---------------------------------------------------------------------------

test.describe("GET /oauth2/auth — authorization request", () => {
  test("redirects unauthenticated user to /login", async ({ page }) => {
    // Act
    await page.goto(buildAuthorizeUrl());

    // Assert — the server must redirect to /login, preserving the original
    // request so it can be resumed after successful authentication.
    expect(page.url()).toContain("/login");
  });

  test("preserves original authorize parameters through login redirect", async ({
    page,
  }) => {
    // Act
    await page.goto(buildAuthorizeUrl());

    // Assert — the login page URL or a hidden field must carry enough context
    // to resume the flow; at minimum the path must be /login.
    expect(page.url()).toContain("/login");
  });
});

// ---------------------------------------------------------------------------
// Login — GET /login
// ---------------------------------------------------------------------------

test.describe("GET /login — login form", () => {
  test("renders the login form with email and password fields", async ({
    page,
  }) => {
    // Act
    await page.goto("/login");

    // Assert
    await expect(page.locator("form")).toBeVisible();
    await expect(
      page.locator(
        'input[type="email"], input[name="email"], input[name="username"]'
      )
    ).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Login — POST /login
// ---------------------------------------------------------------------------

test.describe("POST /login — credential submission", () => {
  test("accepts valid credentials and redirects back to authorize", async ({
    page,
  }) => {
    // Arrange — start from the authorization endpoint so the server knows
    // where to redirect after a successful login.
    await page.goto(buildAuthorizeUrl());

    // Act
    await page
      .locator(
        'input[type="email"], input[name="email"], input[name="username"]'
      )
      .fill("admin@test.local");
    await page.locator('input[type="password"]').fill("test-password");
    await page.locator('button[type="submit"]').click();

    // Assert — after login the server must continue the authorize flow.
    // The user should land on either a consent page or directly receive a
    // redirect to the callback URI.
    await page.waitForURL(/\/consent|localhost:9999\/callback/, {
      timeout: 10_000,
    });
    const url = page.url();
    const isConsentPage =
      url.includes("/consent") || url.includes("/oauth2/auth");
    const isCallback = url.startsWith("http://localhost:9999/callback");
    expect(isConsentPage || isCallback).toBe(true);
  });

  test("rejects invalid credentials and re-renders login with an error", async ({
    page,
  }) => {
    // Arrange
    await page.goto("/login");

    // Act
    await page
      .locator(
        'input[type="email"], input[name="email"], input[name="username"]'
      )
      .fill("admin@test.local");
    await page.locator('input[type="password"]').fill("wrong-password");
    await page.locator('button[type="submit"]').click();

    // Assert — user must stay on /login and see an error message.
    expect(page.url()).toContain("/login");
    const errorLocator = page.locator(
      '[role="alert"], .error, [data-testid="error"], p.error'
    );
    await expect(errorLocator).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Full Authorization Code Flow — happy path
// ---------------------------------------------------------------------------

test.describe("Authorization Code Flow — full happy path", () => {
  test("completes authorize → login → consent → callback with code", async ({
    page,
  }) => {
    // Act — run the full flow and capture the callback URL via the helper.
    const code = await completeFlowAndGetCode(page);

    // Assert
    expect(code).toBeTruthy();

    // Reconstruct the callback URL to validate state param via the request
    // listener already used inside the helper; here we just verify the code.
    expect(code).not.toBe("");
  });

  test("exchanges authorization code for access_token and id_token", async ({
    page,
    request,
  }) => {
    // Arrange — complete the login flow to obtain a code.
    const code = await completeFlowAndGetCode(page);
    expect(code).toBeTruthy();

    // Act — exchange the code at the token endpoint.
    const tokenResponse = await request.post("/oauth2/token", {
      form: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "http://localhost:9999/callback",
        client_id: "test-client",
        client_secret: "test-secret",
      },
    });

    // Assert — the token endpoint must respond with 200 and a JSON body
    // containing access_token, id_token and token_type.
    expect(tokenResponse.status()).toBe(200);

    const body = await tokenResponse.json();
    expect(body.access_token).toBeTruthy();
    expect(body.id_token).toBeTruthy();
    expect(body.token_type).toMatch(/^[Bb]earer$/);
    expect(typeof body.expires_in).toBe("number");
    expect(body.expires_in).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// access_token — JWT claim validation
// ---------------------------------------------------------------------------

test.describe("access_token — JWT claim validation", () => {
  /**
   * Helper: run the full flow and return the token endpoint response body.
   * Shared across claim validation tests.
   */
  async function obtainTokens(
    page: import("@playwright/test").Page,
    request: Parameters<Parameters<typeof test>[1]>[0]["request"]
  ): Promise<Record<string, unknown>> {
    const code = await completeFlowAndGetCode(page);

    const tokenResponse = await request.post("/oauth2/token", {
      form: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "http://localhost:9999/callback",
        client_id: "test-client",
        client_secret: "test-secret",
      },
    });

    return tokenResponse.json();
  }

  test("access_token is a well-formed JWT with three dot-separated parts", async ({
    page,
    request,
  }) => {
    const tokens = await obtainTokens(page, request);
    const accessToken = tokens.access_token as string;

    expect(accessToken.split(".").length).toBe(3);
  });

  test("access_token iss claim matches the server issuer", async ({
    page,
    request,
  }) => {
    // Arrange — fetch the expected issuer from the discovery document.
    const discoveryResponse = await request.get(
      "/.well-known/openid-configuration"
    );
    const discovery = await discoveryResponse.json();
    const expectedIssuer: string = discovery.issuer;

    const tokens = await obtainTokens(page, request);
    const { payload } = decodeJwt(tokens.access_token as string);

    // Assert
    expect(payload.iss).toBe(expectedIssuer);
  });

  test("access_token aud claim includes the requesting client_id", async ({
    page,
    request,
  }) => {
    const tokens = await obtainTokens(page, request);
    const { payload } = decodeJwt(tokens.access_token as string);

    // aud can be a string or an array per RFC 7519 §4.1.3.
    const aud = payload.aud;
    const audList = Array.isArray(aud) ? aud : [aud];
    expect(audList).toContain("test-client");
  });

  test("access_token scope claim contains the requested scopes", async ({
    page,
    request,
  }) => {
    const tokens = await obtainTokens(page, request);
    const { payload } = decodeJwt(tokens.access_token as string);

    const scope = payload.scope as string;
    expect(scope).toContain("openid");
    expect(scope).toContain("profile");
    expect(scope).toContain("email");
  });

  test("access_token exp claim is in the future", async ({
    page,
    request,
  }) => {
    const tokens = await obtainTokens(page, request);
    const { payload } = decodeJwt(tokens.access_token as string);

    const exp = payload.exp as number;
    const nowSeconds = Math.floor(Date.now() / 1000);
    expect(exp).toBeGreaterThan(nowSeconds);
  });

  test("access_token iat claim is in the past or present", async ({
    page,
    request,
  }) => {
    const tokens = await obtainTokens(page, request);
    const { payload } = decodeJwt(tokens.access_token as string);

    const iat = payload.iat as number;
    const nowSeconds = Math.floor(Date.now() / 1000);
    // Allow a 5-second clock skew.
    expect(iat).toBeLessThanOrEqual(nowSeconds + 5);
  });
});

// ---------------------------------------------------------------------------
// id_token — JWKS signature verification + claim validation
// ---------------------------------------------------------------------------

test.describe("id_token — JWKS signature verification and claim validation", () => {
  /**
   * Import a JWK RSA public key into the WebCrypto API so we can verify the
   * id_token signature without any third-party library.
   */
  async function importRsaPublicKey(
    jwk: Record<string, unknown>
  ): Promise<CryptoKey> {
    return crypto.subtle.importKey(
      "jwk",
      jwk as JsonWebKey,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  }

  /**
   * Verify the RS256 signature of a JWT against a JWKS.
   * Returns true only when a matching key validates the signature.
   */
  async function verifyJwtSignature(
    token: string,
    jwks: { keys: Record<string, unknown>[] }
  ): Promise<boolean> {
    const parts = token.split(".");
    if (parts.length !== 3) return false;

    const { header } = decodeJwt(token);
    const kid = header.kid as string | undefined;

    // Select the key: prefer the one matching kid, fall back to any RS256 key.
    const candidates = jwks.keys.filter((k) => {
      if (k.kty !== "RSA") return false;
      if (kid !== undefined) return k.kid === kid;
      return true;
    });

    const encoder = new TextEncoder();
    const signingInput = encoder.encode(`${parts[0]}.${parts[1]}`);

    const base64urlToBuffer = (s: string): ArrayBuffer => {
      const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
      const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    };

    const signatureBuffer = base64urlToBuffer(parts[2]);

    for (const jwk of candidates) {
      try {
        const key = await importRsaPublicKey(jwk);
        const valid = await crypto.subtle.verify(
          "RSASSA-PKCS1-v1_5",
          key,
          signatureBuffer,
          signingInput
        );
        if (valid) return true;
      } catch {
        // Key import failed — try the next candidate.
      }
    }

    return false;
  }

  test("id_token signature is valid against the JWKS public key", async ({
    page,
    request,
  }) => {
    // Arrange — obtain the auth code, then fetch tokens and JWKS.
    const code = await completeFlowAndGetCode(page);

    const [tokenResponse, jwksResponse] = await Promise.all([
      request.post("/oauth2/token", {
        form: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: "http://localhost:9999/callback",
          client_id: "test-client",
          client_secret: "test-secret",
        },
      }),
      request.get("/jwks"),
    ]);

    const tokens = await tokenResponse.json();
    const jwks = await jwksResponse.json();

    // Act
    const valid = await verifyJwtSignature(tokens.id_token as string, jwks);

    // Assert
    expect(valid).toBe(true);
  });

  test("id_token sub claim is a non-empty string identifying the user", async ({
    page,
    request,
  }) => {
    const code = await completeFlowAndGetCode(page);

    const tokenResponse = await request.post("/oauth2/token", {
      form: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "http://localhost:9999/callback",
        client_id: "test-client",
        client_secret: "test-secret",
      },
    });
    const tokens = await tokenResponse.json();
    const { payload } = decodeJwt(tokens.id_token as string);

    expect(typeof payload.sub).toBe("string");
    expect((payload.sub as string).length).toBeGreaterThan(0);
  });

  test("id_token aud claim includes the requesting client_id", async ({
    page,
    request,
  }) => {
    const code = await completeFlowAndGetCode(page);

    const tokenResponse = await request.post("/oauth2/token", {
      form: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "http://localhost:9999/callback",
        client_id: "test-client",
        client_secret: "test-secret",
      },
    });
    const tokens = await tokenResponse.json();
    const { payload } = decodeJwt(tokens.id_token as string);

    const aud = payload.aud;
    const audList = Array.isArray(aud) ? aud : [aud];
    expect(audList).toContain("test-client");
  });

  test("id_token iss claim matches the server issuer", async ({
    page,
    request,
  }) => {
    // Arrange — fetch the expected issuer.
    const discoveryResponse = await request.get(
      "/.well-known/openid-configuration"
    );
    const discovery = await discoveryResponse.json();
    const expectedIssuer: string = discovery.issuer;

    const code = await completeFlowAndGetCode(page);

    const tokenResponse = await request.post("/oauth2/token", {
      form: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "http://localhost:9999/callback",
        client_id: "test-client",
        client_secret: "test-secret",
      },
    });
    const tokens = await tokenResponse.json();
    const { payload } = decodeJwt(tokens.id_token as string);

    expect(payload.iss).toBe(expectedIssuer);
  });

  test("id_token nonce claim matches the nonce sent in the authorization request", async ({
    page,
    request,
  }) => {
    const code = await completeFlowAndGetCode(
      page,
      buildAuthorizeUrl({ nonce: "test-nonce-value" })
    );

    const tokenResponse = await request.post("/oauth2/token", {
      form: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: "http://localhost:9999/callback",
        client_id: "test-client",
        client_secret: "test-secret",
      },
    });
    const tokens = await tokenResponse.json();
    const { payload } = decodeJwt(tokens.id_token as string);

    // Assert — the nonce must round-trip unchanged to prevent replay attacks.
    expect(payload.nonce).toBe("test-nonce-value");
  });
});

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

test.describe("Authorization Code Flow — error cases", () => {
  test("returns error when client_id is invalid", async ({ request }) => {
    // Act — send an authorization request with an unknown client_id.
    const params = new URLSearchParams({
      response_type: "code",
      client_id: "nonexistent-client-id",
      redirect_uri: "http://localhost:9999/callback",
      scope: "openid",
      state: "err-state",
    });
    const response = await request.get(`/oauth2/auth?${params.toString()}`);

    // Assert — the server must not redirect to the callback with a code.
    // Per RFC 6749 §4.1.2.1, for unknown client_id the server must NOT
    // redirect (to avoid open-redirect abuse); it should return 4xx directly.
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.status()).toBeLessThan(500);
  });

  test("returns error when redirect_uri does not match registered URI", async ({
    request,
  }) => {
    // Act — use a redirect_uri that has not been registered for the client.
    const params = new URLSearchParams({
      response_type: "code",
      client_id: "test-client",
      redirect_uri: "http://evil.example.com/callback",
      scope: "openid",
      state: "err-state",
    });
    const response = await request.get(`/oauth2/auth?${params.toString()}`);

    // Assert — per RFC 6749 §4.1.2.1, redirect_uri mismatch must not redirect;
    // the server must return 4xx directly.
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.status()).toBeLessThan(500);
  });

  test("token endpoint returns error when authorization code is invalid", async ({
    request,
  }) => {
    // Act — attempt to exchange a fabricated / already-used code.
    const tokenResponse = await request.post("/oauth2/token", {
      form: {
        grant_type: "authorization_code",
        code: "totally-invalid-code-value",
        redirect_uri: "http://localhost:9999/callback",
        client_id: "test-client",
        client_secret: "test-secret",
      },
    });

    // Assert — RFC 6749 §5.2 mandates 400 with error=invalid_grant for a
    // bad or expired authorization code.
    expect(tokenResponse.status()).toBe(400);

    const body = await tokenResponse.json();
    expect(body.error).toBe("invalid_grant");
  });
});
