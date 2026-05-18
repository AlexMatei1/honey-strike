// /profile — operator profile + badges grid.
//
// Reads:
//   - /api/profile        for username, role, member age, platform stats
//   - /api/lessons        to know which lessons exist for the progress grid
//   - localStorage        for XP / streak / per-action counters
//
// Badge unlock rules live entirely client-side because the platform is
// single-operator — the counters that drive them already accumulate in
// localStorage from mascot_mini.js.

(function () {
  const RANKS = [
    { name: 'Apprentice',  min:    0 },
    { name: 'Sentry',      min:   25 },
    { name: 'Defender',    min:   75 },
    { name: 'Hunter',      min:  150 },
    { name: 'Veteran',     min:  300 },
    { name: 'Threat-OG',   min:  600 },
    { name: 'HoneyMaster', min: 1000 },
  ];

  // Badge catalogue. `check(ctx)` returns true if the badge is unlocked.
  // ctx = { xp, streak, counts, profile, lessonCatalogue }
  const BADGES = [
    { id: 'newcomer',  icon: '🐣', name: 'Newcomer',
      desc: 'Welcome to HoneyStrike.',
      check: () => true },

    { id: 'first-xp',  icon: '⭐', name: 'First XP',
      desc: 'Earned your first XP.',
      check: ({ xp }) => xp > 0 },

    { id: 'apprentice', icon: '📚', name: 'Apprentice',
      desc: 'Reach 50 XP.',
      check: ({ xp }) => xp >= 50 },

    { id: 'veteran', icon: '⚔️', name: 'Veteran',
      desc: 'Reach 250 XP.',
      check: ({ xp }) => xp >= 250 },

    { id: 'honeymaster', icon: '👑', name: 'HoneyMaster',
      desc: 'Reach 1000 XP. Bragging rights unlocked.',
      check: ({ xp }) => xp >= 1000 },

    { id: 'on-streak', icon: '🔥', name: 'On a Streak',
      desc: 'Three correct labels in a row.',
      check: ({ counts }) => (counts.bestStreak || 0) >= 3 },

    { id: 'sharpshooter', icon: '🎯', name: 'Sharpshooter',
      desc: 'Ten correct labels in a row.',
      check: ({ counts }) => (counts.bestStreak || 0) >= 10 },

    { id: 'first-block', icon: '🚫', name: 'First Block',
      desc: 'Blocked your first attacker IP.',
      check: ({ counts }) => (counts.blocks || 0) >= 1 },

    { id: 'wall-builder', icon: '🧱', name: 'Wall Builder',
      desc: 'Blocked 10 attacker IPs.',
      check: ({ counts }) => (counts.blocks || 0) >= 10 },

    { id: 'student',  icon: '🎓', name: 'Student',
      desc: 'Complete your first lesson.',
      check: ({ counts }) => (counts.lessonsDone || 0) >= 1 },

    { id: 'scholar',  icon: '📖', name: 'Scholar',
      desc: 'Complete every attack lesson.',
      check: ({ counts, lessonCatalogue }) => {
        const need = (lessonCatalogue.attack || []).map(l => l.id);
        if (!need.length) return false;
        const done = new Set(counts.lessonsDoneIds || []);
        return need.every(id => done.has(`attack:${id}`));
      } },

    { id: 'detective', icon: '🕵️', name: 'Detective',
      desc: 'Complete every defender lesson.',
      check: ({ counts, lessonCatalogue }) => {
        const need = (lessonCatalogue.defend || []).map(l => l.id);
        if (!need.length) return false;
        const done = new Set(counts.lessonsDoneIds || []);
        return need.every(id => done.has(`defend:${id}`));
      } },

    { id: 'critical-catcher', icon: '💯', name: 'Critical Catcher',
      desc: 'Your honeypot recorded a critical-severity session.',
      check: ({ profile }) => (profile.stats || {}).critical_sessions > 0 },

    { id: 'globalist', icon: '🌍', name: 'Globalist',
      desc: 'Attacks from 5+ countries.',
      check: ({ profile }) => (profile.stats || {}).unique_countries >= 5 },

    { id: 'flag-hunter', icon: '🚩', name: 'Flag Hunter',
      desc: 'Caught a canary string in an attacker session.',
      check: ({ counts }) => (counts.canariesCaught || 0) >= 1 },
  ];

  // ---- localStorage helpers --------------------------------------------
  const LS_XP        = 'hs_xp_v1';
  const LS_STREAK    = 'hs_streak_v1';
  const LS_COUNTS    = 'hs_counts_v1';
  const LS_ACTIVITY  = 'hs_activity_v1';
  const LS_BADGES    = 'hs_badges_v1';

  function readCounts() {
    try { return JSON.parse(localStorage.getItem(LS_COUNTS) || '{}'); }
    catch { return {}; }
  }
  function readActivity() {
    try { return JSON.parse(localStorage.getItem(LS_ACTIVITY) || '[]'); }
    catch { return []; }
  }
  function readBadges() {
    try { return JSON.parse(localStorage.getItem(LS_BADGES) || '{}'); }
    catch { return {}; }
  }
  function writeBadges(b) { localStorage.setItem(LS_BADGES, JSON.stringify(b)); }

  // ---- rank computation ------------------------------------------------
  function rankFor(xp) {
    let cur = RANKS[0], next = null;
    for (let i = 0; i < RANKS.length; i++) {
      if (xp >= RANKS[i].min) cur = RANKS[i];
      else { next = RANKS[i]; break; }
    }
    return { cur, next };
  }

  function fmtRelative(iso) {
    if (!iso) return 'never';
    const d = new Date(iso);
    const diffSec = (Date.now() - d.getTime()) / 1000;
    if (diffSec < 60)        return 'just now';
    if (diffSec < 3600)      return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86_400)    return `${Math.floor(diffSec / 3600)}h ago`;
    if (diffSec < 30 * 86_400) return `${Math.floor(diffSec / 86_400)}d ago`;
    return d.toLocaleDateString();
  }

  // ---- rendering --------------------------------------------------------
  function renderHeader(profile, xp, streak) {
    document.getElementById('profile-username').textContent = profile.username;
    document.getElementById('profile-role').textContent = profile.role;
    document.getElementById('profile-member-for').textContent = `${profile.member_for_days}d`;
    document.getElementById('profile-last-login').textContent = fmtRelative(profile.last_login_at);
    document.getElementById('profile-streak').textContent = streak;

    const { cur, next } = rankFor(xp);
    document.getElementById('profile-rank').textContent = cur.name;
    document.getElementById('profile-xp').textContent = xp;
    const fill = document.getElementById('profile-rank-fill');
    if (next) {
      const span = next.min - cur.min;
      const pct = Math.max(0, Math.min(100, ((xp - cur.min) / span) * 100));
      fill.style.width = pct + '%';
      document.getElementById('profile-next-rank').textContent =
        ` · next: ${next.name} at ${next.min}`;
    } else {
      fill.style.width = '100%';
      document.getElementById('profile-next-rank').textContent = ' · max rank';
    }
  }

  function renderStats(stats) {
    for (const [k, v] of Object.entries(stats)) {
      const el = document.querySelector(`[data-key="${k}"]`);
      if (el) el.textContent = v;
    }
  }

  function renderBadges(ctx) {
    const grid = document.getElementById('badge-grid');
    grid.innerHTML = '';
    const earned = readBadges();
    let newlyEarned = [];
    for (const b of BADGES) {
      const unlocked = b.check(ctx);
      if (unlocked && !earned[b.id]) {
        earned[b.id] = new Date().toISOString();
        newlyEarned.push(b);
      }
      const card = document.createElement('div');
      card.className = `badge ${unlocked ? 'earned' : 'locked'}`;
      card.title = b.desc;
      card.innerHTML = `
        <div class="badge-icon">${unlocked ? b.icon : '🔒'}</div>
        <div class="badge-name">${b.name}</div>
        <div class="badge-desc muted">${b.desc}</div>
        ${unlocked && earned[b.id]
          ? `<div class="badge-when muted">earned ${fmtRelative(earned[b.id])}</div>`
          : ''}
      `;
      grid.appendChild(card);
    }
    writeBadges(earned);
    if (newlyEarned.length && window.HSGame) {
      window.HSGame.react('cheer', `🏅 ${newlyEarned.length} new badge${newlyEarned.length>1?'s':''} unlocked!`);
    }
  }

  function renderLessonProgress(catalogue, counts) {
    const done = new Set(counts.lessonsDoneIds || []);
    function paint(listEl, items, family) {
      listEl.innerHTML = '';
      if (!items.length) { listEl.innerHTML = '<li class="muted">No lessons.</li>'; return; }
      for (const l of items) {
        const id = `${family}:${l.id}`;
        const li = document.createElement('li');
        li.className = done.has(id) ? 'done' : 'todo';
        li.innerHTML = `${done.has(id) ? '✓' : '○'} <a href="/play/${family}/${l.id}">${l.title}</a>
          <span class="muted">${(l.ttps || []).join(' ')}</span>`;
        listEl.appendChild(li);
      }
    }
    paint(document.getElementById('prog-attack'), catalogue.attack || [], 'attack');
    paint(document.getElementById('prog-defend'), catalogue.defend || [], 'defend');
  }

  function renderActivity() {
    const log = readActivity();
    const ol = document.getElementById('activity-log');
    if (!log.length) { return; }                 // keep the default placeholder
    ol.innerHTML = '';
    for (const e of log.slice(0, 30)) {
      const li = document.createElement('li');
      li.innerHTML = `<span class="muted">${fmtRelative(e.t)}</span> ${e.icon || '•'} ${e.text}`;
      ol.appendChild(li);
    }
  }

  // ---- boot ------------------------------------------------------------
  async function load() {
    let profile = { username: '?', role: 'operator', member_for_days: 0, stats: {} };
    try {
      const r = await window.HS.apiFetch('/api/profile');
      if (r.ok) profile = await r.json();
    } catch (e) { /* ignore */ }

    let lessonCatalogue = { attack: [], defend: [] };
    try {
      const r = await window.HS.apiFetch('/api/lessons');
      if (r.ok) lessonCatalogue = await r.json();
    } catch (e) { /* ignore */ }

    const xp = Number(localStorage.getItem(LS_XP) || 0);
    const streak = Number(localStorage.getItem(LS_STREAK) || 0);
    const counts = readCounts();
    const ctx = { xp, streak, counts, profile, lessonCatalogue };

    renderHeader(profile, xp, streak);
    renderStats(profile.stats || {});
    renderBadges(ctx);
    renderLessonProgress(lessonCatalogue, counts);
    renderActivity();
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    load();
  });
})();
