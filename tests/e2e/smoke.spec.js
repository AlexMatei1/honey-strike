// Smoke tests: every dashboard page loads, authenticates, and shows its key
// elements. Catches regressions in routing, auth, the dock, and the JS that
// hydrates each page.

const { test, expect } = require('@playwright/test');
const { login, dismissBriefing } = require('./helpers');

test.beforeEach(async ({ page }) => {
  await login(page);
});

test('live map: stats + map + dock render', async ({ page }) => {
  await page.goto('/');
  await dismissBriefing(page);
  await expect(page.locator('#overview')).toBeVisible();
  await expect(page.locator('#map')).toBeVisible();
  await expect(page.locator('.dock')).toBeVisible();
  await expect(page.locator('.dock-btn[data-dock="dashboard"]')).toHaveClass(/active/);
  await expect(page.locator('#xp-value')).toBeVisible();
});

test('sessions list renders', async ({ page }) => {
  await page.goto('/sessions');
  await dismissBriefing(page);
  await expect(page.locator('table')).toBeVisible();
  await expect(page.locator('.dock-btn[data-dock="sessions"]')).toHaveClass(/active/);
});

test('analytics renders', async ({ page }) => {
  await page.goto('/analytics');
  await dismissBriefing(page);
  await expect(page.locator('.dock-btn[data-dock="analytics"]')).toHaveClass(/active/);
});

test('play hubs list lessons', async ({ page }) => {
  await page.goto('/play/attack');
  await dismissBriefing(page);
  await expect(page.locator('.lesson-card').first()).toBeVisible({ timeout: 10_000 });
  const attackCount = await page.locator('.lesson-card').count();
  expect(attackCount).toBeGreaterThanOrEqual(8);

  await page.goto('/play/defend');
  await dismissBriefing(page);
  await expect(page.locator('.lesson-card').first()).toBeVisible({ timeout: 10_000 });
  const defendCount = await page.locator('.lesson-card').count();
  expect(defendCount).toBeGreaterThanOrEqual(8);
});

test('a lesson page loads its code stage + mascot', async ({ page }) => {
  await page.goto('/play/attack/ssh-hydra');
  await expect(page.locator('#lesson-title')).not.toHaveText('Loading…', { timeout: 10_000 });
  await expect(page.locator('#lesson-code .block').first()).toBeVisible();
  await expect(page.locator('#mascot')).toBeVisible();
});

test('war room renders', async ({ page }) => {
  await page.goto('/warroom');
  await dismissBriefing(page);
  await expect(page.locator('.warroom')).toBeVisible();
});

test('profile shows badges grid + rank', async ({ page }) => {
  await page.goto('/profile');
  await dismissBriefing(page);
  await expect(page.locator('#badge-grid .badge').first()).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('#profile-rank')).toBeVisible();
});

test('command palette opens with Ctrl+K and filters', async ({ page }) => {
  await page.goto('/');
  await dismissBriefing(page);
  await page.keyboard.press('Control+k');
  await expect(page.locator('#cmdk-overlay')).toBeVisible();
  await page.fill('#cmdk-input', 'sessions');
  await expect(page.locator('.cmdk-item').first()).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#cmdk-overlay')).toBeHidden();
});
