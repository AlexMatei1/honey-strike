// /profile — operator profile, now server-backed.
//
// Reads:
//   /api/profile   username, role, member age, platform stats
//   /api/progress  xp, streak, rank, badges[], counts, activity (per account)
//   /api/lessons   lesson catalogue for the progress grid
//
// XP/badges/activity are no longer in localStorage — they live in the DB and
// follow the account across devices.

(function () {
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
  function esc(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function renderHeader(profile, progress) {
    document.getElementById('profile-username').textContent = profile.username;
    const roleLabel = profile.role === 'admin' ? 'SOC Lead 🛡' : 'Analyst 🔍';
    document.getElementById('profile-role').textContent = roleLabel;
    document.getElementById('profile-member-for').textContent = `${profile.member_for_days}d`;
    document.getElementById('profile-last-login').textContent = fmtRelative(profile.last_login_at);
    document.getElementById('profile-streak').textContent = progress.streak || 0;

    const rank = progress.rank || { name: 'Apprentice', pct: 0, next: null, next_at: null };
    document.getElementById('profile-rank').textContent = rank.name;
    document.getElementById('profile-xp').textContent = progress.xp || 0;
    document.getElementById('profile-rank-fill').style.width = (rank.pct || 0) + '%';
    document.getElementById('profile-next-rank').textContent =
      rank.next ? ` · next: ${rank.next} at ${rank.next_at}` : ' · max rank';
  }

  function renderStats(stats) {
    for (const [k, v] of Object.entries(stats || {})) {
      const el = document.querySelector(`[data-key="${k}"]`);
      if (el) el.textContent = v;
    }
  }

  function renderBadges(badges) {
    const grid = document.getElementById('badge-grid');
    grid.innerHTML = '';
    for (const b of (badges || [])) {
      const card = document.createElement('div');
      card.className = `badge ${b.earned ? 'earned' : 'locked'}`;
      card.title = b.desc;
      card.innerHTML = `
        <div class="badge-icon">${b.earned ? b.icon : '🔒'}</div>
        <div class="badge-name">${esc(b.name)}</div>
        <div class="badge-desc muted">${esc(b.desc)}</div>
        ${b.earned && b.earned_at ? `<div class="badge-when muted">earned ${fmtRelative(b.earned_at)}</div>` : ''}
      `;
      grid.appendChild(card);
    }
  }

  function renderLessonProgress(catalogue, counts) {
    const done = new Set((counts || {}).lessonsDoneIds || []);
    function paint(listEl, items, family) {
      listEl.innerHTML = '';
      if (!items.length) { listEl.innerHTML = '<li class="muted">No lessons.</li>'; return; }
      for (const l of items) {
        const id = `${family}:${l.id}`;
        const li = document.createElement('li');
        li.className = done.has(id) ? 'done' : 'todo';
        li.innerHTML = `${done.has(id) ? '✓' : '○'} <a href="/play/${family}/${l.id}">${esc(l.title)}</a>
          <span class="muted">${(l.ttps || []).join(' ')}</span>`;
        listEl.appendChild(li);
      }
    }
    paint(document.getElementById('prog-attack'), catalogue.attack || [], 'attack');
    paint(document.getElementById('prog-defend'), catalogue.defend || [], 'defend');
  }

  function renderActivity(activity) {
    const ol = document.getElementById('activity-log');
    if (!activity || !activity.length) return;     // keep the placeholder
    ol.innerHTML = '';
    for (const e of activity.slice(0, 30)) {
      const li = document.createElement('li');
      li.innerHTML = `<span class="muted">${fmtRelative(e.t)}</span> ${e.icon || '•'} ${esc(e.text)}`;
      ol.appendChild(li);
    }
  }

  async function getJSON(path) {
    try { const r = await window.HS.apiFetch(path); return r.ok ? await r.json() : null; }
    catch { return null; }
  }

  async function load() {
    const [profile, progress, catalogue] = await Promise.all([
      getJSON('/api/profile'),
      getJSON('/api/progress'),
      getJSON('/api/lessons'),
    ]);
    if (profile && progress) renderHeader(profile, progress);
    if (profile) renderStats(profile.stats);
    if (progress) { renderBadges(progress.badges); renderActivity(progress.activity); }
    if (catalogue && progress) renderLessonProgress(catalogue, progress.counts);
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    load();
  });
})();
