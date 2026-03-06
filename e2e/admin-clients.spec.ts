import { test, expect } from "@playwright/test";

/**
 * Admin Clients CRUD e2e specs.
 *
 * Covers the full Admin Client management API for the five CRUD endpoints:
 *   - POST   /api/admin/clients         — create a new OAuth client
 *   - GET    /api/admin/clients         — list all OAuth clients
 *   - GET    /api/admin/clients/:id     — retrieve a single OAuth client
 *   - PUT    /api/admin/clients/:id     — update an existing OAuth client
 *   - DELETE /api/admin/clients/:id     — delete an OAuth client
 *
 * All tests in this file are skipped (DLD-682) until implemented.
 * Remove each `test.skip()` once the feature is in place.
 *
 * Prerequisites (not yet satisfied — hence the skips):
 *   - POST   /api/admin/clients   endpoint registered
 *   - GET    /api/admin/clients   endpoint registered
 *   - GET    /api/admin/clients/:id endpoint registered
 *   - PUT    /api/admin/clients/:id endpoint registered
 *   - DELETE /api/admin/clients/:id endpoint registered
 *   - Admin Bearer token authentication middleware registered
 *   - storage.DeleteClient implemented
 *   - storage.UpdateClient implemented
 *   - storage.ListClients implemented
 *
 * Parent issue: DLD-577 (MyAuth — 개인 인프라용 OAuth/OIDC Server)
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/** Base path for all Admin client management endpoints. */
const ADMIN_CLIENTS_ENDPOINT = "/api/admin/clients";

/**
 * Placeholder admin Bearer token.
 * Replace with a real token value once the Admin auth mechanism is implemented.
 */
const ADMIN_BEARER_TOKEN = "admin-bearer-token-placeholder-dld682";

/**
 * Token endpoint used to verify that a deleted client can no longer authenticate.
 */
const TOKEN_ENDPOINT = "/oauth2/token";

// ---------------------------------------------------------------------------
// Helper: build the Authorization header for Admin API requests.
// ---------------------------------------------------------------------------

function adminAuthHeader(): string {
  return `Bearer ${ADMIN_BEARER_TOKEN}`;
}

// ---------------------------------------------------------------------------
// Helper: build Basic Auth header for client_secret_basic OAuth authentication.
// ---------------------------------------------------------------------------

function basicAuthHeader(clientId: string, clientSecret: string): string {
  const encoded = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64"
  );
  return `Basic ${encoded}`;
}

// ---------------------------------------------------------------------------
// Helper: build a minimal valid client creation payload.
// Returns a unique client_id each call to avoid cross-test collisions.
// ---------------------------------------------------------------------------

function buildClientPayload(suffix: string): Record<string, unknown> {
  return {
    id: `e2e-client-${suffix}`,
    redirect_uris: ["http://localhost:9000/callback"],
    grant_types: ["client_credentials"],
    response_types: ["token"],
    scopes: ["read", "write"],
    token_endpoint_auth_method: "client_secret_basic",
    is_public: false,
  };
}

// ---------------------------------------------------------------------------
// 1. POST /api/admin/clients — 클라이언트 생성 (happy path)
//    생성 성공, 응답에 client_secret 포함 검증
// ---------------------------------------------------------------------------

test.describe("POST /api/admin/clients — create client happy path", () => {
  test(
    "creates a new OAuth client and returns client_secret in the response",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — build a unique client payload for this test run.
      const payload = buildClientPayload("create-" + Date.now());

      // Act — POST to the admin clients endpoint with a valid Admin Bearer token.
      const response = await request.post(ADMIN_CLIENTS_ENDPOINT, {
        headers: {
          Authorization: adminAuthHeader(),
          "Content-Type": "application/json",
        },
        data: JSON.stringify(payload),
      });

      // Assert — the server must respond HTTP 201 Created.
      expect(response.status()).toBe(201);

      const body = await response.json();

      // The response must echo back the client_id.
      expect(body.id).toBe(payload.id);

      // client_secret must be present in the creation response (plain-text,
      // before bcrypt hashing).  This is the only time the secret is revealed.
      expect(typeof body.client_secret).toBe("string");
      expect((body.client_secret as string).length).toBeGreaterThan(0);

      // Core fields must be reflected back.
      expect(body.redirect_uris).toEqual(payload.redirect_uris);
      expect(body.grant_types).toEqual(payload.grant_types);
      expect(body.token_endpoint_auth_method).toBe(
        payload.token_endpoint_auth_method
      );
      expect(body.is_public).toBe(false);
    }
  );
});

// ---------------------------------------------------------------------------
// 2. POST /api/admin/clients — 인증 없이 생성 시도 → 401
// ---------------------------------------------------------------------------

test.describe("POST /api/admin/clients — error: missing admin token", () => {
  test(
    "returns 401 when the Authorization header is absent",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — build a valid payload but omit the Authorization header.
      const payload = buildClientPayload("unauth-" + Date.now());

      // Act — POST without the admin Bearer token.
      const response = await request.post(ADMIN_CLIENTS_ENDPOINT, {
        headers: {
          "Content-Type": "application/json",
        },
        data: JSON.stringify(payload),
      });

      // Assert — the server must reject the request with 401 Unauthorized.
      expect(response.status()).toBe(401);
    }
  );
});

// ---------------------------------------------------------------------------
// 3. GET /api/admin/clients — 클라이언트 목록 조회 (happy path)
//    client_secret 미포함 검증
// ---------------------------------------------------------------------------

test.describe("GET /api/admin/clients — list clients happy path", () => {
  test(
    "returns a list of clients without client_secret in any entry",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — create a client first so the list is non-empty.
      const payload = buildClientPayload("list-" + Date.now());

      const createResponse = await request.post(ADMIN_CLIENTS_ENDPOINT, {
        headers: {
          Authorization: adminAuthHeader(),
          "Content-Type": "application/json",
        },
        data: JSON.stringify(payload),
      });
      expect(createResponse.status()).toBe(201);

      // Act — GET the full client list.
      const listResponse = await request.get(ADMIN_CLIENTS_ENDPOINT, {
        headers: {
          Authorization: adminAuthHeader(),
        },
      });

      // Assert — HTTP 200 with a JSON array.
      expect(listResponse.status()).toBe(200);

      const body = await listResponse.json();
      expect(Array.isArray(body)).toBe(true);
      expect((body as unknown[]).length).toBeGreaterThan(0);

      // client_secret MUST NOT appear in any list entry (security requirement).
      for (const client of body as Record<string, unknown>[]) {
        expect(client.client_secret).toBeUndefined();
        // id must be present for each entry.
        expect(typeof client.id).toBe("string");
        expect((client.id as string).length).toBeGreaterThan(0);
      }

      // The newly created client must appear in the list.
      const ids = (body as Record<string, unknown>[]).map((c) => c.id);
      expect(ids).toContain(payload.id);
    }
  );
});

// ---------------------------------------------------------------------------
// 4. GET /api/admin/clients/:id — 단일 클라이언트 상세 조회 (happy path)
// ---------------------------------------------------------------------------

test.describe("GET /api/admin/clients/:id — get single client happy path", () => {
  test(
    "returns the client detail by id without client_secret",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — create a client to retrieve.
      const payload = buildClientPayload("get-" + Date.now());

      const createResponse = await request.post(ADMIN_CLIENTS_ENDPOINT, {
        headers: {
          Authorization: adminAuthHeader(),
          "Content-Type": "application/json",
        },
        data: JSON.stringify(payload),
      });
      expect(createResponse.status()).toBe(201);

      // Act — GET /api/admin/clients/:id for the newly created client.
      const getResponse = await request.get(
        `${ADMIN_CLIENTS_ENDPOINT}/${payload.id}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
          },
        }
      );

      // Assert — HTTP 200 with the correct client object.
      expect(getResponse.status()).toBe(200);

      const body = await getResponse.json();

      // id must match the requested client.
      expect(body.id).toBe(payload.id);

      // client_secret must NOT be present in the detail response.
      expect(body.client_secret).toBeUndefined();

      // Core fields must be returned.
      expect(body.redirect_uris).toEqual(payload.redirect_uris);
      expect(body.grant_types).toEqual(payload.grant_types);
      expect(body.token_endpoint_auth_method).toBe(
        payload.token_endpoint_auth_method
      );
    }
  );
});

// ---------------------------------------------------------------------------
// 5. GET /api/admin/clients/:id — 존재하지 않는 클라이언트 → 404
// ---------------------------------------------------------------------------

test.describe("GET /api/admin/clients/:id — error: not found", () => {
  test(
    "returns 404 when the requested client id does not exist",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — a client id that was never created.
      const nonExistentId = "does-not-exist-dld682-" + Date.now();

      // Act — GET /api/admin/clients/:id for the non-existent client.
      const response = await request.get(
        `${ADMIN_CLIENTS_ENDPOINT}/${nonExistentId}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
          },
        }
      );

      // Assert — the server must respond with 404 Not Found.
      expect(response.status()).toBe(404);
    }
  );
});

// ---------------------------------------------------------------------------
// 6. PUT /api/admin/clients/:id — 클라이언트 수정 (happy path)
// ---------------------------------------------------------------------------

test.describe("PUT /api/admin/clients/:id — update client happy path", () => {
  test(
    "updates the client fields and reflects the changes on subsequent GET",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — create a client to modify.
      const payload = buildClientPayload("update-" + Date.now());

      const createResponse = await request.post(ADMIN_CLIENTS_ENDPOINT, {
        headers: {
          Authorization: adminAuthHeader(),
          "Content-Type": "application/json",
        },
        data: JSON.stringify(payload),
      });
      expect(createResponse.status()).toBe(201);

      // Arrange — build an updated payload with a different redirect_uri and scopes.
      const updatedPayload = {
        ...payload,
        redirect_uris: ["http://localhost:9001/callback"],
        scopes: ["read"],
      };

      // Act — PUT /api/admin/clients/:id with the updated fields.
      const updateResponse = await request.put(
        `${ADMIN_CLIENTS_ENDPOINT}/${payload.id}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
            "Content-Type": "application/json",
          },
          data: JSON.stringify(updatedPayload),
        }
      );

      // Assert — the server must respond with 200 OK.
      expect(updateResponse.status()).toBe(200);

      // Assert — GET the client and verify the changes were persisted.
      const getResponse = await request.get(
        `${ADMIN_CLIENTS_ENDPOINT}/${payload.id}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
          },
        }
      );
      expect(getResponse.status()).toBe(200);

      const body = await getResponse.json();
      expect(body.redirect_uris).toEqual(updatedPayload.redirect_uris);
      expect(body.scopes).toEqual(updatedPayload.scopes);
    }
  );
});

// ---------------------------------------------------------------------------
// 7. PUT /api/admin/clients/:id — 존재하지 않는 클라이언트 수정 → 404
// ---------------------------------------------------------------------------

test.describe("PUT /api/admin/clients/:id — error: not found", () => {
  test(
    "returns 404 when trying to update a client that does not exist",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — a client id that was never created.
      const nonExistentId = "does-not-exist-update-dld682-" + Date.now();

      // Act — PUT /api/admin/clients/:id for the non-existent client.
      const response = await request.put(
        `${ADMIN_CLIENTS_ENDPOINT}/${nonExistentId}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
            "Content-Type": "application/json",
          },
          data: JSON.stringify(buildClientPayload(nonExistentId)),
        }
      );

      // Assert — the server must respond with 404 Not Found.
      expect(response.status()).toBe(404);
    }
  );
});

// ---------------------------------------------------------------------------
// 8. DELETE /api/admin/clients/:id — 클라이언트 삭제 (happy path)
//    삭제 후 해당 클라이언트로 OAuth 인증 불가 확인
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/clients/:id — delete client happy path", () => {
  test(
    "deletes the client and the client can no longer authenticate via client_credentials",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — create a client with client_credentials grant so that it can
      // attempt token requests.  Capture the plain-text client_secret from the
      // creation response.
      const suffix = "delete-" + Date.now();
      const payload = buildClientPayload(suffix);

      const createResponse = await request.post(ADMIN_CLIENTS_ENDPOINT, {
        headers: {
          Authorization: adminAuthHeader(),
          "Content-Type": "application/json",
        },
        data: JSON.stringify(payload),
      });
      expect(createResponse.status()).toBe(201);

      const createBody = await createResponse.json();
      const clientId = createBody.id as string;
      const clientSecret = createBody.client_secret as string;

      // Sanity check — the client can authenticate before deletion.
      const preDeleteToken = await request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(clientId, clientSecret),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "client_credentials",
          scope: "read",
        }).toString(),
      });
      expect(preDeleteToken.status()).toBe(200);

      // Act — DELETE /api/admin/clients/:id.
      const deleteResponse = await request.delete(
        `${ADMIN_CLIENTS_ENDPOINT}/${clientId}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
          },
        }
      );

      // Assert — the server must respond with 204 No Content on successful deletion.
      expect(deleteResponse.status()).toBe(204);

      // Assert — the client no longer exists (GET returns 404).
      const getAfterDelete = await request.get(
        `${ADMIN_CLIENTS_ENDPOINT}/${clientId}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
          },
        }
      );
      expect(getAfterDelete.status()).toBe(404);

      // Assert — the deleted client can no longer obtain an access_token via
      // the OAuth client_credentials grant.  The server must reject the request
      // because the client_id no longer exists in the client store.
      const postDeleteToken = await request.post(TOKEN_ENDPOINT, {
        headers: {
          Authorization: basicAuthHeader(clientId, clientSecret),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: new URLSearchParams({
          grant_type: "client_credentials",
          scope: "read",
        }).toString(),
      });

      // RFC 6749 §5.2: the server must return 401 invalid_client because the
      // client_id no longer exists in the registered client store.
      expect(postDeleteToken.status()).toBe(401);
      const tokenBody = await postDeleteToken.json();
      expect(tokenBody.error).toBe("invalid_client");
    }
  );
});

// ---------------------------------------------------------------------------
// 9. DELETE /api/admin/clients/:id — 존재하지 않는 클라이언트 삭제 → 404
// ---------------------------------------------------------------------------

test.describe("DELETE /api/admin/clients/:id — error: not found", () => {
  test(
    "returns 404 when trying to delete a client that does not exist",
    async ({ request }) => {
      // Activated: Admin API is implemented

      // Arrange — a client id that was never created.
      const nonExistentId = "does-not-exist-delete-dld682-" + Date.now();

      // Act — DELETE /api/admin/clients/:id for the non-existent client.
      const response = await request.delete(
        `${ADMIN_CLIENTS_ENDPOINT}/${nonExistentId}`,
        {
          headers: {
            Authorization: adminAuthHeader(),
          },
        }
      );

      // Assert — the server must respond with 404 Not Found.
      expect(response.status()).toBe(404);
    }
  );
});
