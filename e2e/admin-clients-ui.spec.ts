import { test, expect } from "@playwright/test";

/**
 * Admin SPA — Clients UI e2e specs.
 *
 * All tests in this file are skipped (DLD-688) until the Clients page UI is
 * implemented in the Admin SPA.
 * Remove each `test.skip()` call once the corresponding UI feature is in place.
 *
 * Covers the Admin SPA UI for OAuth client management:
 *   - GET  /admin/clients  — 클라이언트 목록 카드 표시 확인
 *   - UI   "클라이언트 추가" 버튼 → 풀스크린 시트 열림 확인
 *   - UI   클라이언트 생성 폼 입력 → 생성 → 목록에 추가됨 확인
 *   - UI   클라이언트 생성 직후 client_secret 표시 + 복사 확인
 *   - UI   카드 탭 → 상세 정보 펼침 확인
 *   - UI   편집 버튼 → 폼 수정 → 변경사항 반영 확인
 *   - UI   삭제 버튼 → 확인 → 목록에서 제거됨 확인
 *
 * Prerequisites (not yet satisfied — hence the skips):
 *   - /admin/clients route registered in React Router (App.tsx)
 *   - ClientsPage component implemented
 *   - "클라이언트" nav item added to BottomNav
 *   - 클라이언트 추가 풀스크린 시트(모달) 구현
 *   - 클라이언트 카드 컴포넌트 구현
 *   - 카드 상세 펼침(accordion) 구현
 *   - 편집/삭제 UI 구현
 *
 * Parent issue: DLD-577 (MyAuth — 개인 인프라용 OAuth/OIDC Server)
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/** Route for the Admin SPA login page. */
const ADMIN_LOGIN_PATH = "/admin/login";

/** Route for the Admin SPA clients page. */
const ADMIN_CLIENTS_PATH = "/admin/clients";

/** Admin credentials matching the seeded test configuration. */
const ADMIN_ID = "admin@test.local";
const ADMIN_PASSWORD = "test-password";

// ---------------------------------------------------------------------------
// Helper: log in to the Admin SPA and land on the clients page.
// Encapsulates the repeated login + navigation Arrange steps.
// ---------------------------------------------------------------------------

async function loginAndGoToClients(
  page: import("@playwright/test").Page
): Promise<void> {
  await page.goto(ADMIN_LOGIN_PATH);
  await page.getByPlaceholder("admin").fill(ADMIN_ID);
  await page.locator('input[type="password"]').fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: /관리자 로그인/i }).click();
  await page.goto(ADMIN_CLIENTS_PATH);
  await expect(page).toHaveURL(ADMIN_CLIENTS_PATH);
}

// ---------------------------------------------------------------------------
// 1. 클라이언트 목록 카드 표시 확인
//    /admin/clients 페이지에 등록된 클라이언트가 카드 형태로 표시되는지 검증
// ---------------------------------------------------------------------------

test.describe("GET /admin/clients — 클라이언트 목록 카드 렌더링", () => {
  test(
    "displays registered clients as cards with id and grant_types visible",
    async ({ page }) => {

      // Arrange — log in and navigate to the clients page.
      await loginAndGoToClients(page);

      // Assert — at least one client card must be visible on the page.
      // The seeded test client (SEED_TEST_CLIENT=1) guarantees a non-empty list.
      const clientCards = page.locator(
        "[data-testid='client-card'], .client-card, [role='listitem']"
      );
      await expect(clientCards.first()).toBeVisible();

      // Assert — each visible card must show the client id.
      // The seeded client id is "test-client".
      await expect(
        page.getByText("test-client")
      ).toBeVisible();

      // Assert — grant type information must appear somewhere on the card.
      await expect(
        page
          .getByText(/client_credentials|authorization_code|grant/i)
          .first()
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 2. "클라이언트 추가" 버튼 → 풀스크린 시트 열림 확인
//    버튼 클릭 시 풀스크린 시트(모달/다이얼로그)가 열리는지 검증
// ---------------------------------------------------------------------------

test.describe("UI — '클라이언트 추가' 버튼 → 풀스크린 시트", () => {
  test(
    "opens a fullscreen sheet when the '클라이언트 추가' button is clicked",
    async ({ page }) => {

      // Arrange — log in and navigate to the clients page.
      await loginAndGoToClients(page);

      // Act — click the '클라이언트 추가' button.
      await page
        .getByRole("button", { name: /클라이언트 추가/i })
        .click();

      // Assert — a fullscreen sheet / dialog / modal must become visible.
      // Match by role=dialog or a known sheet selector.
      await expect(
        page
          .getByRole("dialog")
          .or(page.locator("[data-testid='client-sheet']"))
          .or(page.locator(".fullscreen-sheet, .sheet, .modal"))
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 3. 클라이언트 생성 폼 입력 및 생성 → 목록에 추가됨 확인
//    풀스크린 시트에서 폼을 작성하고 생성 버튼을 클릭한 뒤
//    목록에 새 클라이언트 카드가 추가되는지 검증
// ---------------------------------------------------------------------------

test.describe("UI — 클라이언트 생성 폼 → 목록에 추가됨", () => {
  test(
    "creates a new client via the form and shows the new client card in the list",
    async ({ page }) => {

      // Arrange — log in, navigate to clients page, open the add-client sheet.
      await loginAndGoToClients(page);
      await page
        .getByRole("button", { name: /클라이언트 추가/i })
        .click();
      await expect(
        page
          .getByRole("dialog")
          .or(page.locator("[data-testid='client-sheet']"))
      ).toBeVisible();

      // Arrange — build a unique client id to avoid conflicts across test runs.
      const newClientId = `e2e-ui-client-${Date.now()}`;

      // Act — fill in the client creation form.
      // Client ID field
      await page
        .getByLabel(/client id|클라이언트 id/i)
        .fill(newClientId);

      // Redirect URI field
      await page
        .getByLabel(/redirect uri|리다이렉트 uri/i)
        .fill("http://localhost:9000/callback");

      // Grant types — select or check 'client_credentials'
      const grantTypeInput = page
        .getByLabel(/grant type/i)
        .or(page.getByRole("checkbox", { name: /client_credentials/i }))
        .or(page.getByRole("option", { name: /client_credentials/i }));
      await grantTypeInput.first().click();

      // Response types — select or check 'token'
      const responseTypeInput = page
        .getByLabel(/response type/i)
        .or(page.getByRole("checkbox", { name: /^token$/i }))
        .or(page.getByRole("option", { name: /^token$/i }));
      await responseTypeInput.first().click();

      // Scopes field
      await page
        .getByLabel(/scope/i)
        .fill("read write");

      // Act — submit the form.
      await page
        .getByRole("button", { name: /생성|추가|저장|create|add|save/i })
        .click();

      // Assert — the sheet must close after successful creation.
      await expect(
        page
          .getByRole("dialog")
          .or(page.locator("[data-testid='client-sheet']"))
      ).not.toBeVisible();

      // Assert — the new client card must appear in the list.
      await expect(page.getByText(newClientId)).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 4. Client Secret 최초 생성 시 표시 + 복사 가능 확인
//    클라이언트 생성 직후 client_secret이 한 번 표시되고
//    복사 버튼으로 클립보드에 복사 가능한지 검증
// ---------------------------------------------------------------------------

test.describe("UI — Client Secret 최초 표시 + 복사", () => {
  test(
    "shows the client_secret once after creation and allows copying it to the clipboard",
    async ({ page, context }) => {

      // Arrange — grant clipboard-write permission so the copy action works.
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);

      // Arrange — log in, navigate to clients page, open the add-client sheet.
      await loginAndGoToClients(page);
      await page
        .getByRole("button", { name: /클라이언트 추가/i })
        .click();

      const newClientId = `e2e-secret-client-${Date.now()}`;

      // Act — fill in the minimal form and submit.
      await page
        .getByLabel(/client id|클라이언트 id/i)
        .fill(newClientId);
      await page
        .getByLabel(/redirect uri|리다이렉트 uri/i)
        .fill("http://localhost:9000/callback");
      await page
        .getByRole("button", { name: /생성|추가|저장|create|add|save/i })
        .click();

      // Assert — a client_secret disclosure area must appear immediately after
      // creation.  The secret is only shown once (RFC 6749 / security best practice).
      const secretDisplay = page
        .getByTestId("client-secret-display")
        .or(page.locator("[data-testid='client-secret']"))
        .or(page.getByText(/client.?secret/i).locator(".."));
      await expect(secretDisplay).toBeVisible();

      // Assert — the secret value must be a non-empty string.
      const secretText = await secretDisplay.textContent();
      expect(secretText).toBeTruthy();
      expect((secretText as string).trim().length).toBeGreaterThan(0);

      // Act — click the copy button adjacent to the secret.
      await page
        .getByRole("button", { name: /복사|copy/i })
        .click();

      // Assert — the clipboard must now contain the secret value.
      const clipboardText = await page.evaluate(
        async () => await navigator.clipboard.readText()
      );
      expect(clipboardText.trim().length).toBeGreaterThan(0);
    }
  );
});

// ---------------------------------------------------------------------------
// 5. 카드 탭 → 상세 펼침 확인
//    클라이언트 카드를 클릭/탭하면 상세 정보가 펼쳐지는지 검증
//    (redirect_uris, grant_types, response_types, scopes,
//     token_endpoint_auth_method, is_public)
// ---------------------------------------------------------------------------

test.describe("UI — 카드 탭 → 상세 펼침", () => {
  test(
    "expands client detail when the client card is clicked, showing all fields",
    async ({ page }) => {

      // Arrange — log in and navigate to the clients page.
      // The seeded test-client provides a known card to interact with.
      await loginAndGoToClients(page);

      // Arrange — locate the seeded test-client card.
      const clientCard = page
        .locator("[data-testid='client-card']")
        .filter({ hasText: "test-client" })
        .or(page.locator(".client-card").filter({ hasText: "test-client" }))
        .or(page.getByRole("listitem").filter({ hasText: "test-client" }));
      await expect(clientCard.first()).toBeVisible();

      // Act — click the card to expand the detail panel.
      await clientCard.first().click();

      // Assert — the detail section must become visible after the tap.
      // It should contain the key fields from adminClientResponse.
      await expect(
        page
          .getByTestId("client-detail")
          .or(page.locator(".client-detail, [aria-expanded='true']"))
      ).toBeVisible();

      // Assert — redirect_uris must be listed in the detail.
      await expect(
        page.getByText(/redirect.?uri/i).first()
      ).toBeVisible();

      // Assert — grant_types must be listed.
      await expect(
        page.getByText(/grant.?type/i).first()
      ).toBeVisible();

      // Assert — response_types must be listed.
      await expect(
        page.getByText(/response.?type/i).first()
      ).toBeVisible();

      // Assert — scopes must be listed.
      await expect(
        page.getByText(/scope/i).first()
      ).toBeVisible();

      // Assert — token_endpoint_auth_method must be listed.
      await expect(
        page.getByText(/token.?endpoint.?auth|auth.?method/i).first()
      ).toBeVisible();

      // Assert — is_public flag must be indicated.
      await expect(
        page.getByText(/is.?public|public.?client/i).first()
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 6. 편집 동작 확인
//    상세 펼침에서 편집 버튼 클릭 → 폼으로 수정 → 변경사항이 목록에 반영됨 검증
// ---------------------------------------------------------------------------

test.describe("UI — 편집 버튼 → 폼 수정 → 변경사항 반영", () => {
  test(
    "updates the client when fields are edited through the edit form and saves",
    async ({ page }) => {

      // Arrange — log in and navigate to the clients page.
      await loginAndGoToClients(page);

      // Arrange — expand the seeded test-client card.
      const clientCard = page
        .locator("[data-testid='client-card']")
        .filter({ hasText: "test-client" })
        .or(page.locator(".client-card").filter({ hasText: "test-client" }))
        .or(page.getByRole("listitem").filter({ hasText: "test-client" }));
      await clientCard.first().click();

      // Arrange — open the edit form via the edit button.
      await page
        .getByRole("button", { name: /편집|수정|edit/i })
        .click();

      // Assert — the edit form / sheet must be visible.
      await expect(
        page
          .getByRole("dialog")
          .or(page.locator("[data-testid='client-edit-sheet']"))
          .or(page.locator(".edit-sheet, .edit-form"))
      ).toBeVisible();

      // Act — modify the scopes field to a new value.
      const scopesInput = page
        .getByLabel(/scope/i)
        .or(page.locator("input[name='scopes'], textarea[name='scopes']"));
      await scopesInput.clear();
      await scopesInput.fill("read");

      // Act — save the changes.
      await page
        .getByRole("button", { name: /저장|수정 완료|save|update/i })
        .click();

      // Assert — the edit form must close after saving.
      await expect(
        page
          .getByRole("dialog")
          .or(page.locator("[data-testid='client-edit-sheet']"))
      ).not.toBeVisible();

      // Assert — the updated scope must be reflected somewhere on the page
      // (either in the card or after re-expanding the detail).
      await expect(page.getByText(/\bread\b/).first()).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 7. 삭제 동작 확인
//    상세 펼침에서 삭제 버튼 클릭 → 확인 다이얼로그 → 목록에서 제거됨 검증
// ---------------------------------------------------------------------------

test.describe("UI — 삭제 버튼 → 확인 → 목록에서 제거됨", () => {
  test(
    "removes the client from the list after delete is confirmed",
    async ({ page, request }) => {

      // Arrange — create a dedicated client via the Admin API so we do not
      // delete the shared seeded test-client and break other tests.
      const deleteTargetId = `e2e-delete-target-${Date.now()}`;
      const createRes = await request.post("/api/admin/clients", {
        headers: {
          Authorization: "Bearer admin-bearer-token-placeholder-dld682",
          "Content-Type": "application/json",
        },
        data: JSON.stringify({
          id: deleteTargetId,
          redirect_uris: ["http://localhost:9000/callback"],
          grant_types: ["client_credentials"],
          response_types: ["token"],
          scopes: ["read"],
          token_endpoint_auth_method: "client_secret_basic",
          is_public: false,
        }),
      });
      expect(createRes.status()).toBe(201);

      // Arrange — log in and navigate to the clients page.
      await loginAndGoToClients(page);

      // Arrange — wait for the newly created client card to appear.
      await expect(page.getByText(deleteTargetId)).toBeVisible();

      // Arrange — expand the card to reveal the delete button.
      const clientCard = page
        .locator("[data-testid='client-card']")
        .filter({ hasText: deleteTargetId })
        .or(page.locator(".client-card").filter({ hasText: deleteTargetId }))
        .or(page.getByRole("listitem").filter({ hasText: deleteTargetId }));
      await clientCard.first().click();

      // Act — click the delete button.
      await page
        .getByRole("button", { name: /삭제|delete|remove/i })
        .click();

      // Act — confirm the deletion in the confirmation dialog.
      // The dialog may use '확인', '삭제', 'Confirm', 'Yes', etc.
      await expect(
        page
          .getByRole("dialog")
          .or(page.locator("[data-testid='confirm-dialog']"))
          .or(page.locator(".confirm-dialog, .alert-dialog"))
      ).toBeVisible();
      await page
        .getByRole("button", { name: /확인|삭제|confirm|yes/i })
        .click();

      // Assert — the deleted client card must no longer be visible in the list.
      await expect(page.getByText(deleteTargetId)).not.toBeVisible();
    }
  );
});
