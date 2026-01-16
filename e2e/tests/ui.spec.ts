import { test, expect } from "@playwright/test";

test.describe("KeyMeld UI", () => {
  test.describe("Dashboard", () => {
    test("loads successfully", async ({ page }) => {
      await page.goto("/");

      // Check page title
      await expect(page).toHaveTitle(/KeyMeld/);

      // Check navbar is present
      await expect(page.locator("nav.navbar")).toBeVisible();

      // Check main title "KeyMeld Admin" is visible
      await expect(
        page.getByRole("heading", { name: /KeyMeld Admin/i }),
      ).toBeVisible();
    });

    test("displays stats cards", async ({ page }) => {
      await page.goto("/");

      // Wait for stats to load (they may be loaded via HTMX)
      const statsSection = page.locator("#stats-cards").first();
      await expect(statsSection).toBeVisible({ timeout: 10000 });

      // Check for stat labels - these should be present even with zero values
      await expect(
        page
          .getByText(/Healthy Enclaves|Active Sessions|Total Sessions/i)
          .first(),
      ).toBeVisible();
    });

    test("displays enclaves section", async ({ page }) => {
      await page.goto("/");

      // Check for "Enclave Overview" section on dashboard
      await expect(
        page.getByRole("heading", { name: /Enclave Overview/i }),
      ).toBeVisible();
    });

    test("displays sessions section", async ({ page }) => {
      await page.goto("/");

      // Check for "Recent Sessions" section heading on dashboard
      await expect(
        page.getByRole("heading", { name: /Recent Sessions/i }),
      ).toBeVisible();
    });
  });

  test.describe("Sessions Page", () => {
    test("loads successfully", async ({ page }) => {
      await page.goto("/sessions");

      // Check page loads
      await expect(page).toHaveTitle(/KeyMeld/);

      // Check for "All Sessions" heading
      await expect(
        page.getByRole("heading", { name: /All Sessions/i }),
      ).toBeVisible();
    });

    test("displays sessions table or empty state", async ({ page }) => {
      await page.goto("/sessions");

      // Either a table with sessions or an empty state message should be visible
      const hasTable = await page
        .locator("table")
        .isVisible()
        .catch(() => false);
      const hasEmptyState = await page
        .getByText(/No sessions|empty/i)
        .isVisible()
        .catch(() => false);

      expect(hasTable || hasEmptyState).toBeTruthy();
    });
  });

  test.describe("Enclaves Page", () => {
    test("loads successfully", async ({ page }) => {
      await page.goto("/enclaves");

      // Check page loads
      await expect(page).toHaveTitle(/KeyMeld/);

      // Check for enclaves heading - the page has "All Enclaves"
      await expect(
        page.getByRole("heading", { name: /Enclaves/i }).first(),
      ).toBeVisible();
    });

    test("displays enclave cards", async ({ page }) => {
      await page.goto("/enclaves");

      // Wait for enclave data to load
      await page.waitForLoadState("networkidle");

      // Should show enclave information (cards or list items)
      const enclaveContent = page.locator(".card, .enclave-card, .box").first();
      await expect(enclaveContent).toBeVisible({ timeout: 10000 });
    });
  });

  test.describe("Navigation", () => {
    test("navbar links work correctly", async ({ page }) => {
      await page.goto("/");

      // Navigate to Sessions
      await page.getByRole("link", { name: /Sessions/i }).click();
      await expect(page).toHaveURL(/\/sessions/);

      // Navigate to Enclaves
      await page.getByRole("link", { name: /Enclaves/i }).click();
      await expect(page).toHaveURL(/\/enclaves/);

      // Navigate back to Dashboard
      await page.getByRole("link", { name: /Dashboard/i }).click();
      await expect(page).toHaveURL(/\/$/);
    });

    test("brand link returns to dashboard", async ({ page }) => {
      await page.goto("/sessions");

      // Click the "KeyMeld Admin" title link to go back to dashboard
      await page.getByRole("link", { name: /KeyMeld Admin/i }).click();
      await expect(page).toHaveURL(/\/$/);
    });
  });

  test.describe("Theme Toggle", () => {
    test("theme toggle is present", async ({ page }) => {
      await page.goto("/");

      // Check for theme toggle button (has id="theme-toggle")
      const themeToggle = page.locator("#theme-toggle");
      await expect(themeToggle).toBeVisible();
    });
  });

  test.describe("API Docs", () => {
    test("API documentation page loads", async ({ page }) => {
      await page.goto("/api/v1/docs");

      // Wait for the docs to load (Scalar UI)
      await page.waitForLoadState("networkidle");

      // The docs page should have loaded some content
      await expect(page.locator("body")).not.toBeEmpty();
    });
  });

  test.describe("Health Check", () => {
    test("health endpoint returns successfully", async ({ request }) => {
      const response = await request.get("/api/v1/health");
      expect(response.ok()).toBeTruthy();
    });

    test("detailed health endpoint returns status info", async ({
      request,
    }) => {
      const response = await request.get("/api/v1/health/detail");
      expect(response.ok()).toBeTruthy();

      const body = await response.json();
      expect(body).toHaveProperty("status");
      expect(body).toHaveProperty("healthy_enclaves");
      expect(body).toHaveProperty("total_enclaves");
    });
  });
});
