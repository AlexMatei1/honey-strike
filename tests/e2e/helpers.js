// Shared helpers for the e2e specs.

const ADMIN_USER = process.env.E2E_ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || 'change-me-strong-password';

/**
 * Log in via the login form. The app stores the JWT in sessionStorage and
 * redirects to /, so after this the page (same context) is authenticated.
 */
async function login(page) {
  await page.goto('/login');
  await page.fill('input[name="username"]', ADMIN_USER);
  await page.fill('input[name="password"]', ADMIN_PASS);
  await Promise.all([
    page.waitForURL('**/'),
    page.click('button[type="submit"]'),
  ]);
  // sessionStorage token is set; give the dashboard a beat to boot.
  await page.waitForTimeout(300);
}

/** Dismiss the first-visit briefing overlay if it's showing. */
async function dismissBriefing(page) {
  const skip = page.locator('#briefing-skip-btn');
  try {
    if (await skip.isVisible({ timeout: 1500 })) {
      await skip.click();
      await page.waitForTimeout(150);
    }
  } catch { /* no overlay */ }
}

module.exports = { login, dismissBriefing, ADMIN_USER, ADMIN_PASS };
