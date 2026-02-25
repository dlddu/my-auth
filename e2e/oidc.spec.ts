import { test, expect } from "@playwright/test";

/**
 * OIDC Discovery & JWKS e2e specs.
 *
 * All tests in this file are skipped (DLD-580) until the server implements
 * the /.well-known/openid-configuration and /jwks endpoints.  Remove the
 * `test.skip()` calls once the server is implemented.
 *
 * TODO: Activate when DLD-580 is implemented.
 */

// ---------------------------------------------------------------------------
// OIDC Discovery — /.well-known/openid-configuration
// ---------------------------------------------------------------------------

test.describe("GET /.well-known/openid-configuration", () => {
  test("returns HTTP 200", async ({ request }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/.well-known/openid-configuration");

    // Assert
    expect(response.status()).toBe(200);
  });

  test("returns Content-Type: application/json", async ({ request }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/.well-known/openid-configuration");

    // Assert
    const contentType = response.headers()["content-type"];
    expect(contentType).toContain("application/json");
  });

  test("response body contains all required OIDC Discovery fields", async ({
    request,
  }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/.well-known/openid-configuration");
    const body = await response.json();

    // Assert — all seven OIDC Discovery spec required fields must be present
    // and non-empty.
    expect(body.issuer).toBeTruthy();
    expect(body.authorization_endpoint).toBeTruthy();
    expect(body.token_endpoint).toBeTruthy();
    expect(body.jwks_uri).toBeTruthy();

    expect(Array.isArray(body.response_types_supported)).toBe(true);
    expect(body.response_types_supported.length).toBeGreaterThan(0);

    expect(Array.isArray(body.subject_types_supported)).toBe(true);
    expect(body.subject_types_supported.length).toBeGreaterThan(0);

    expect(Array.isArray(body.id_token_signing_alg_values_supported)).toBe(
      true
    );
    expect(
      body.id_token_signing_alg_values_supported.length
    ).toBeGreaterThan(0);
  });

  test("jwks_uri field is a valid URL", async ({ request }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/.well-known/openid-configuration");
    const body = await response.json();

    // Assert — jwks_uri must parse as an absolute URL without throwing.
    expect(() => new URL(body.jwks_uri)).not.toThrow();
    const parsed = new URL(body.jwks_uri);
    expect(parsed.protocol).toMatch(/^https?:$/);
  });
});

// ---------------------------------------------------------------------------
// JWKS — /jwks
// ---------------------------------------------------------------------------

test.describe("GET /jwks", () => {
  test("returns HTTP 200", async ({ request }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/jwks");

    // Assert
    expect(response.status()).toBe(200);
  });

  test("returns Content-Type: application/json", async ({ request }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/jwks");

    // Assert
    const contentType = response.headers()["content-type"];
    expect(contentType).toContain("application/json");
  });

  test("response body is a valid JWK Set with a keys array", async ({
    request,
  }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/jwks");
    const body = await response.json();

    // Assert — RFC 7517 JWK Set format requires a top-level "keys" array.
    expect(body).toHaveProperty("keys");
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys.length).toBeGreaterThan(0);
  });

  test("response contains at least one RSA public key", async ({
    request,
  }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/jwks");
    const body = await response.json();

    // Assert — at least one JWK must have kty === "RSA".
    const rsaKeys = body.keys.filter(
      (key: Record<string, unknown>) => key.kty === "RSA"
    );
    expect(rsaKeys.length).toBeGreaterThan(0);
  });

  test("RSA key does not expose private key fields", async ({ request }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/jwks");
    const body = await response.json();

    // Assert — private key components must never appear in a public JWKS
    // endpoint (RFC 7517 §9.3 security consideration).
    const privateFields = ["d", "p", "q", "dp", "dq", "qi"];
    for (const key of body.keys) {
      for (const field of privateFields) {
        expect(key).not.toHaveProperty(
          field,
          `RSA key (kid=${key.kid}) must not expose private field "${field}"`
        );
      }
    }
  });
});

// ---------------------------------------------------------------------------
// JWKS — JWT signature verification readiness
// ---------------------------------------------------------------------------

test.describe("JWKS public key usability for JWT signature verification", () => {
  test("RSA public key contains all fields required for JWT verification", async ({
    request,
  }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/jwks");
    const body = await response.json();
    const rsaKeys = body.keys.filter(
      (key: Record<string, unknown>) => key.kty === "RSA"
    );
    expect(rsaKeys.length).toBeGreaterThan(0);

    // Assert — each RSA public key must carry the minimum fields a JWT library
    // needs to verify an RS256/RS384/RS512 signature.
    const requiredFields = ["n", "e", "kty", "kid", "use", "alg"];
    for (const key of rsaKeys) {
      for (const field of requiredFields) {
        expect(key).toHaveProperty(
          field,
          `RSA key must have required field "${field}"`
        );
        expect((key as Record<string, unknown>)[field]).toBeTruthy();
      }
    }
  });

  test("RSA public key modulus and exponent are base64url encoded strings", async ({
    request,
  }) => {
    // TODO: Activate when DLD-580 is implemented
    test.skip();

    // Act
    const response = await request.get("/jwks");
    const body = await response.json();
    const rsaKeys = body.keys.filter(
      (key: Record<string, unknown>) => key.kty === "RSA"
    );
    expect(rsaKeys.length).toBeGreaterThan(0);

    // Assert — n (modulus) and e (exponent) must be non-empty base64url
    // strings. A 2048-bit RSA modulus encodes to ~342 base64url characters.
    const base64urlPattern = /^[A-Za-z0-9_-]+$/;
    for (const key of rsaKeys) {
      expect(typeof key.n).toBe("string");
      expect((key.n as string).length).toBeGreaterThanOrEqual(10);
      expect(base64urlPattern.test(key.n as string)).toBe(true);

      expect(typeof key.e).toBe("string");
      expect((key.e as string).length).toBeGreaterThan(0);
      expect(base64urlPattern.test(key.e as string)).toBe(true);
    }
  });
});
