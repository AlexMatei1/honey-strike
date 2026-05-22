// Member-vs-member duel through the web UI: two browser contexts.

const { test, expect } = require('@playwright/test');

async function register(page) {
  const username = 'duel_' + Date.now() + '_' + Math.floor(Math.random() * 1e4);
  await page.goto('/login');
  await page.click('#toggle-link');
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', 'duel-pass-123');
  await Promise.all([page.waitForURL('**/'), page.click('#submit-btn')]);
  return username;
}

test('two members run a duel end to end', async ({ browser }) => {
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const a = await ctxA.newPage();
  const b = await ctxB.newPage();

  // Suppress first-visit briefing overlays so they don't intercept clicks.
  const briefKeys = ['dashboard', 'duel', 'play'];
  for (const p of [a, b]) {
    await p.addInitScript((keys) => {
      for (const k of keys) localStorage.setItem('hs_briefed_' + k, '1');
    }, briefKeys);
  }

  const userA = await register(a);
  const userB = await register(b);

  // A challenges B from the duel page.
  await a.goto('/play/duel');
  await a.waitForSelector(`#opponent option[value="${userB}"]`, { state: 'attached', timeout: 8000 });
  await a.selectOption('#opponent', userB);
  await a.click('#challenge-form button[type="submit"]');
  await expect(a.locator('#challenge-msg')).toContainText(/sent/i, { timeout: 8000 });

  // B sees + accepts the challenge.
  await b.goto('/play/duel');
  const accept = b.locator('#duel-inbox button[data-act="accept"]');
  await expect(accept).toBeVisible({ timeout: 8000 });
  await accept.click();

  // A's arena shows fire buttons; fire one wave.
  await expect(a.locator('#duel-arena')).toBeVisible({ timeout: 8000 });
  const fireBtn = a.locator('#duel-arena button[data-fire="http-recon"]');
  await expect(fireBtn).toBeVisible({ timeout: 8000 });
  await fireBtn.click();

  // B's arena shows the incoming wave with a label input; block it correctly.
  await expect(b.locator('#duel-arena .duel-waves li')).toBeVisible({ timeout: 8000 });
  const input = b.locator('#duel-arena input[data-wave]').first();
  await expect(input).toBeVisible({ timeout: 8000 });
  await input.fill('T1592');
  await b.locator('#duel-arena button[data-label]').first().click();

  // The defender's score climbs to 10 (blocked wave).
  await expect(b.locator('#duel-arena .duel-waves .ok').first()).toBeVisible({ timeout: 8000 });

  await ctxA.close();
  await ctxB.close();
});
