// Role-based UI: SOC Lead (admin) vs Analyst (member).

const { test, expect } = require('@playwright/test');
const { login } = require('./helpers');

async function registerMember(page) {
  const username = 'role_' + Date.now() + Math.floor(Math.random() * 1000);
  await page.goto('/login');
  await page.click('#toggle-link');
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', 'analyst-pass-1');
  await Promise.all([page.waitForURL('**/'), page.click('#submit-btn')]);
  return username;
}

test('admin sees SOC Lead badge + Users dock item', async ({ page }) => {
  await login(page);                 // logs in as admin
  await page.goto('/');
  const badge = page.locator('#role-badge');
  await expect(badge).toBeVisible({ timeout: 8000 });
  await expect(badge).toContainText('SOC Lead');
  await expect(page.locator('#dock-admin')).toBeVisible();
});

test('admin can open the Users page', async ({ page }) => {
  await login(page);
  await page.goto('/admin/users');
  await expect(page.locator('.users-table')).toBeVisible({ timeout: 8000 });
  await expect(page.locator('#users-tbody tr').first()).toBeVisible();
});

test('member sees Analyst badge, no Users dock, locked fire button', async ({ page }) => {
  await registerMember(page);
  await page.goto('/');
  const badge = page.locator('#role-badge');
  await expect(badge).toBeVisible({ timeout: 8000 });
  await expect(badge).toContainText('Analyst');
  await expect(page.locator('#dock-admin')).toBeHidden();

  // On a lesson, the "Fire live" button is locked for members.
  await page.goto('/play/attack/ssh-hydra');
  await page.waitForSelector('#fire-live-btn');
  await expect(page.locator('#fire-live-btn')).toHaveClass(/ui-locked/, { timeout: 8000 });
});

test('member is denied the Users page', async ({ page }) => {
  await registerMember(page);
  await page.goto('/admin/users');
  await expect(page.locator('#users-denied')).toBeVisible({ timeout: 8000 });
});
