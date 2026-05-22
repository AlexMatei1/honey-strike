// Registration flow through the login page UI.

const { test, expect } = require('@playwright/test');

test('create account → lands on dashboard authenticated', async ({ page }) => {
  await page.goto('/login');

  // The "create account" toggle only appears when registration is enabled.
  const toggle = page.locator('#toggle-link');
  await expect(toggle).toBeVisible({ timeout: 5000 });
  await toggle.click();
  await expect(page.locator('#submit-btn')).toHaveText('Create account');

  const username = 'e2e_' + Date.now();
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', 'e2e-password-123');
  await Promise.all([
    page.waitForURL('**/'),
    page.click('#submit-btn'),
  ]);

  // Authenticated: the dashboard stat tiles render and a token is stored.
  await expect(page.locator('#overview')).toBeVisible({ timeout: 10_000 });
  const token = await page.evaluate(() => sessionStorage.getItem('hs_access_token'));
  expect(token).toBeTruthy();
});

test('duplicate username shows an error', async ({ page }) => {
  // Register once, then try the same name again in a fresh context.
  const username = 'dup_' + Date.now();
  await page.goto('/login');
  await page.click('#toggle-link');
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', 'e2e-password-123');
  await Promise.all([page.waitForURL('**/'), page.click('#submit-btn')]);

  // Second attempt, same username.
  await page.goto('/login');
  await page.evaluate(() => sessionStorage.clear());
  await page.click('#toggle-link');
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', 'e2e-password-123');
  await page.click('#submit-btn');
  await expect(page.locator('#login-error')).toBeVisible();
  await expect(page.locator('#login-error')).toContainText(/taken/i);
});
