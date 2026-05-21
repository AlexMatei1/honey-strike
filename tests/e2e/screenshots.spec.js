// Capture marketing screenshots into docs/screenshots/. Run with:
//   E2E_BASE_URL=http://127.0.0.1:8001 npx playwright test screenshots.spec.js
// Then they're embedded in the README.

const { test } = require('@playwright/test');
const path = require('path');
const { login, dismissBriefing } = require('./helpers');

const OUT = path.resolve(__dirname, '../../docs/screenshots');

const BRIEF_KEYS = [
  'dashboard', 'sessions', 'analytics', 'warroom',
  'play_attack', 'play_defend', 'play', 'profile', 'session_detail',
];

test.beforeEach(async ({ page }) => {
  // Pre-mark every page's first-visit briefing as seen so marketing shots are
  // clean (no overlay). addInitScript runs before app JS on every navigation.
  await page.addInitScript((keys) => {
    for (const k of keys) localStorage.setItem('hs_briefed_' + k, '1');
  }, BRIEF_KEYS);
  await login(page);
});

test('shot: live map', async ({ page }) => {
  await page.goto('/');
  await dismissBriefing(page);
  await page.waitForTimeout(2500);          // let the map tiles + markers settle
  await page.screenshot({ path: path.join(OUT, 'live-map.png'), fullPage: false });
});

test('shot: attack lesson (typing + mascot)', async ({ page }) => {
  await page.goto('/play/attack/ssh-hydra');
  await page.waitForSelector('#lesson-code .block');
  await page.waitForTimeout(800);
  // Type a few correct chars so the mascot is mid-"happy" and the stage shows progress.
  await page.keyboard.type('attempts = 0', { delay: 25 });
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(OUT, 'lesson-attack.png'), fullPage: false });
});

test('shot: defender lesson grade', async ({ page }) => {
  await page.goto('/play/defend/detect-password-guess');
  await page.waitForSelector('#lesson-briefing');
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT, 'lesson-defend.png'), fullPage: false });
});

test('shot: profile + badges', async ({ page }) => {
  // Seed some XP/badges in localStorage so the page looks earned, not empty.
  await page.goto('/profile');
  await page.evaluate(() => {
    localStorage.setItem('hs_xp_v1', '180');
    localStorage.setItem('hs_streak_v1', '4');
    localStorage.setItem('hs_counts_v1', JSON.stringify({
      blocks: 3, lessonsDone: 5, correctLabels: 12, bestStreak: 7,
      canariesCaught: 2, lessonsDoneIds: [
        'attack:ssh-hydra', 'attack:http-recon', 'defend:detect-password-guess',
      ],
    }));
  });
  await page.reload();
  await dismissBriefing(page);
  await page.waitForSelector('#badge-grid .badge');
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(OUT, 'profile.png'), fullPage: false });
});

test('shot: war room', async ({ page }) => {
  await page.goto('/warroom');
  await dismissBriefing(page);
  await page.waitForTimeout(2500);
  await page.screenshot({ path: path.join(OUT, 'warroom.png'), fullPage: false });
});

test('shot: command palette', async ({ page }) => {
  await page.goto('/');
  await dismissBriefing(page);
  await page.keyboard.press('Control+k');
  await page.waitForSelector('#cmdk-overlay:not([hidden])');
  await page.fill('#cmdk-input', 'fire');
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(OUT, 'command-palette.png'), fullPage: false });
});
