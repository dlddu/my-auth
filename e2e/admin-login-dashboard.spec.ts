import { test, expect } from "@playwright/test";

/**
 * Admin SPA — Login & Dashboard e2e specs.
 *
 * Covers the Admin SPA UI for the login flow and the dashboard page:
 *   - GET  /admin/login  — Admin 로그인 페이지 렌더링
 *   - POST /admin/login  — 정상 로그인 후 대시보드 진입 (happy path)
 *   - POST /admin/login  — 잘못된 자격증명 입력 시 에러 메시지 표시 (error case)
 *   - GET  /admin        — 대시보드 통계 카드 4개 렌더링 확인
 *   - GET  /admin        — 최근 활동 리스트 섹션 표시 확인
 *
 * All tests in this file are skipped (DLD-686) until the Admin SPA is implemented.
 * Remove each `test.skip()` once the feature is in place.
 *
 * Prerequisites (not yet satisfied — hence the skips):
 *   - Admin SPA React application built and served at /admin
 *   - Admin login page rendered at /admin/login
 *   - Admin authentication endpoint registered
 *   - Dashboard statistics API endpoints registered
 *   - Recent activity API endpoint registered
 *
 * Parent issue: DLD-577 (MyAuth — 개인 인프라용 OAuth/OIDC Server)
 */

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/** Route for the Admin SPA login page. */
const ADMIN_LOGIN_PATH = "/admin/login";

/** Route for the Admin SPA dashboard. */
const ADMIN_DASHBOARD_PATH = "/admin";

/**
 * Placeholder admin credentials.
 * Replace with real credentials once the Admin auth mechanism is implemented.
 */
const ADMIN_ID = "admin@test.local";
const ADMIN_PASSWORD = "test-password";

// ---------------------------------------------------------------------------
// 1. Admin 로그인 페이지 렌더링 확인
//    /admin/login 접근 시 아이디/비밀번호 입력 + '관리자 로그인' 버튼이 표시되는지 검증
// ---------------------------------------------------------------------------

test.describe("GET /admin/login — 로그인 페이지 렌더링", () => {
  test(
    "displays the admin login form with id/password fields and the login button",
    async ({ page }) => {
      // Act — navigate to the Admin login page.
      await page.goto(ADMIN_LOGIN_PATH);

      // Assert — the page heading must identify this as the Admin login page.
      await expect(
        page.getByRole("heading", { name: /myauth admin/i })
      ).toBeVisible();

      // Assert — the id input field must be present (placeholder: 'admin').
      await expect(page.getByPlaceholder("admin")).toBeVisible();

      // Assert — the password input field must be present.
      await expect(
        page.getByRole("textbox", { name: /비밀번호|password/i }).or(
          page.locator('input[type="password"]')
        )
      ).toBeVisible();

      // Assert — the submit button must be labeled '관리자 로그인'.
      await expect(
        page.getByRole("button", { name: /관리자 로그인/i })
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 2. 정상 로그인 후 대시보드 진입 (happy path)
//    올바른 Admin ID/PW 입력 → 대시보드 페이지로 이동하는지 검증
// ---------------------------------------------------------------------------

test.describe("POST /admin/login — 정상 로그인 happy path", () => {
  test(
    "navigates to the admin dashboard after submitting valid credentials",
    async ({ page }) => {
      // Arrange — navigate to the Admin login page.
      await page.goto(ADMIN_LOGIN_PATH);

      // Act — fill in the valid admin credentials and submit.
      await page.getByPlaceholder("admin").fill(ADMIN_ID);
      await page.locator('input[type="password"]').fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /관리자 로그인/i }).click();

      // Assert — the browser must navigate to the Admin dashboard.
      await expect(page).toHaveURL(ADMIN_DASHBOARD_PATH);
    }
  );
});

// ---------------------------------------------------------------------------
// 3. 잘못된 자격증명 입력 시 에러 메시지 표시 (error case)
//    존재하지 않는 ID 또는 틀린 PW 입력 → 에러 메시지가 표시되는지 검증
// ---------------------------------------------------------------------------

test.describe("POST /admin/login — error: invalid credentials", () => {
  test(
    "displays an error message when incorrect credentials are submitted",
    async ({ page }) => {
      // Arrange — navigate to the Admin login page.
      await page.goto(ADMIN_LOGIN_PATH);

      // Act — fill in wrong credentials and submit.
      await page.getByPlaceholder("admin").fill("wrong-admin");
      await page.locator('input[type="password"]').fill("wrong-password");
      await page.getByRole("button", { name: /관리자 로그인/i }).click();

      // Assert — the page must remain on /admin/login (no redirect to dashboard).
      await expect(page).toHaveURL(ADMIN_LOGIN_PATH);

      // Assert — an error message must be visible to the user.
      // The exact text may vary; match any visible error indicator.
      await expect(
        page
          .getByRole("alert")
          .or(page.locator(".error-banner"))
          .or(page.getByText(/invalid|incorrect|잘못|인증 실패/i))
      ).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 4. 대시보드 통계 카드 4개 렌더링 확인
//    로그인 후 대시보드에서 클라이언트/활성 세션/토큰/24h 인증 카드가 표시되는지 검증
// ---------------------------------------------------------------------------

test.describe("GET /admin — 대시보드 통계 카드 렌더링", () => {
  test(
    "shows four stat cards: 클라이언트, 활성 세션, 토큰, 24h 인증",
    async ({ page }) => {
      // Arrange — log in first to reach the dashboard.
      await page.goto(ADMIN_LOGIN_PATH);
      await page.getByPlaceholder("admin").fill(ADMIN_ID);
      await page.locator('input[type="password"]').fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /관리자 로그인/i }).click();
      await expect(page).toHaveURL(ADMIN_DASHBOARD_PATH);

      // Assert — all four stat cards must be visible on the dashboard.
      await expect(page.getByText(/클라이언트/i).first()).toBeVisible();
      await expect(page.getByText(/활성 세션/i).first()).toBeVisible();
      await expect(page.getByText(/토큰/i).first()).toBeVisible();
      await expect(page.getByText(/24h 인증/i).first()).toBeVisible();
    }
  );
});

// ---------------------------------------------------------------------------
// 5. 최근 활동 리스트 섹션 표시 확인
//    로그인 후 대시보드에서 '최근 활동' 섹션이 표시되는지 검증
// ---------------------------------------------------------------------------

test.describe("GET /admin — 최근 활동 리스트 섹션", () => {
  test(
    "displays the recent activity section on the dashboard",
    async ({ page }) => {
      // Arrange — log in first to reach the dashboard.
      await page.goto(ADMIN_LOGIN_PATH);
      await page.getByPlaceholder("admin").fill(ADMIN_ID);
      await page.locator('input[type="password"]').fill(ADMIN_PASSWORD);
      await page.getByRole("button", { name: /관리자 로그인/i }).click();
      await expect(page).toHaveURL(ADMIN_DASHBOARD_PATH);

      // Assert — the '최근 활동' section heading must be visible.
      await expect(page.getByText(/최근 활동/i).first()).toBeVisible();

      // Assert — the recent activity list must contain at least one item.
      // Activity items include events such as Token 발급/갱신, 로그인 성공, Device 인증.
      await expect(page.locator("ul, ol, [role='list']").first()).toBeVisible();
    }
  );
});
