// /play/arena — open PvP arena (free-for-all during a 'PvP window').
// Polls /api/arena/state; renders fire buttons + shared wave feed + scoreboard.
// Leads see open/close controls.

(function () {
  const adminEl = document.getElementById('arena-admin');
  const stateEl = document.getElementById('arena-state');
  let scenarios = [];
  let isAdmin = false;
  let me = '';

  const TTP_HINTS = ['T1110.001', 'T1110.004', 'T1190', 'T1083', 'T1592', 'T1595.001', 'T1078'];

  function esc(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  async function api(path, opts) { return window.HS.apiFetch(path, opts); }

  async function loadScenarios() {
    const r = await api('/api/arena/scenarios');
    if (r.ok) scenarios = await r.json();
  }

  function renderAdmin(open) {
    if (!isAdmin) { adminEl.hidden = true; return; }
    adminEl.hidden = false;
    adminEl.className = 'duel-pane';
    adminEl.innerHTML = open
      ? `<button id="arena-close">⏹ Close the PvP window</button>`
      : `<label>Open a window for
           <select id="arena-dur">
             <option value="300">5 min</option>
             <option value="600" selected>10 min</option>
             <option value="1800">30 min</option>
           </select></label>
         <button id="arena-open">▶ Open PvP window</button>`;
    const ob = document.getElementById('arena-open');
    const cb = document.getElementById('arena-close');
    if (ob) ob.addEventListener('click', async () => {
      await api('/api/arena/open', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ duration_seconds: Number(document.getElementById('arena-dur').value) }),
      });
      refresh();
    });
    if (cb) cb.addEventListener('click', async () => { await api('/api/arena/close', { method: 'POST' }); refresh(); });
  }

  function render(s) {
    renderAdmin(s.open);
    if (!s.open) {
      stateEl.innerHTML = `<div class="duel-pane"><p class="muted">⏸ No PvP window is open right now.
        ${isAdmin ? 'Open one above to start a round.' : 'Ask a SOC Lead to open a round.'}</p></div>`;
      if (s.scoreboard && s.scoreboard.length) stateEl.innerHTML += scoreboardHtml(s.scoreboard, 'Last round');
      return;
    }
    const mins = Math.floor(s.seconds_left / 60), secs = s.seconds_left % 60;
    const timer = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;

    let html = `<div id="arena-arena">
      <div class="duel-head">
        <div class="duel-vs"><span class="you">🎯 PvP window LIVE</span></div>
        <div class="duel-timer ${s.seconds_left <= 30 ? 'low' : ''}">${timer}</div>
      </div>
      <p class="muted">🚀 Fire a wave (anyone) — or label someone else's wave to block it.</p>
      <div class="duel-fire">` +
      scenarios.map(sc => `<button data-fire="${sc.id}">🚀 ${esc(sc.label)}</button>`).join('') +
      `</div><ol class="duel-waves">`;
    for (const w of (s.waves || [])) {
      let right;
      if (w.resolved) {
        right = w.blocked_by
          ? `<span class="ok">✓ blocked by ${esc(w.blocked_by)} (${esc((w.expected_ttps || []).join(', '))})</span>`
          : `<span class="bad">⚠ got through</span>`;
      } else if (w.fired_by === me) {
        right = `<span class="muted">your wave — waiting…</span>`;
      } else {
        right = `<input list="arena-ttps" data-wave="${w.id}" placeholder="T1110.001" maxlength="16">
                 <button data-label="${w.id}">Block</button>`;
      }
      html += `<li><span class="wave-name">🌊 ${esc(w.label)} <span class="muted">by ${esc(w.fired_by)}</span></span> ${right}</li>`;
    }
    html += `</ol></div>`;
    html += scoreboardHtml(s.scoreboard, 'Scoreboard');
    stateEl.innerHTML = html;

    stateEl.querySelectorAll('button[data-fire]').forEach(b =>
      b.addEventListener('click', () => fire(b.dataset.fire, b)));
    stateEl.querySelectorAll('button[data-label]').forEach(b =>
      b.addEventListener('click', () => labelWave(b.dataset.label)));
  }

  function scoreboardHtml(rows, title) {
    if (!rows || !rows.length) return '';
    return `<div class="duel-pane"><h2>🏆 ${title}</h2>
      <table class="users-table"><thead><tr><th>Player</th><th>Points</th></tr></thead>
      <tbody>${rows.map((r, i) =>
        `<tr><td>${i === 0 ? '🥇 ' : ''}${esc(r.username)}${r.username === me ? ' <span class="muted">(you)</span>' : ''}</td><td>${r.points}</td></tr>`
      ).join('')}</tbody></table></div>`;
  }

  async function fire(scenario, btn) {
    if (btn) btn.disabled = true;
    const r = await api('/api/arena/fire', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
    if (!r.ok && window.HSGame) { let m = `HTTP ${r.status}`; try { const j = await r.json(); if (j.detail) m = j.detail; } catch {} window.HSGame.woops(m); }
    setTimeout(() => { if (btn) btn.disabled = false; }, 600);
    refresh();
  }

  async function labelWave(waveId) {
    const input = stateEl.querySelector(`input[data-wave="${waveId}"]`);
    const ttp = (input && input.value || '').trim();
    if (!ttp) return;
    const r = await api('/api/arena/label', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ wave_id: waveId, technique_id: ttp }),
    });
    if (r.ok) {
      const out = await r.json();
      if (window.HSGame) out.correct ? window.HSGame.flash('✓ Blocked! +10') : window.HSGame.woops('✗ Wrong technique');
    }
    refresh();
  }

  async function refresh() {
    const r = await api('/api/arena/state');
    if (!r.ok) return;
    const s = await r.json();
    me = s.you;
    render(s);
  }

  function injectTtps() {
    if (document.getElementById('arena-ttps')) return;
    const dl = document.createElement('datalist');
    dl.id = 'arena-ttps';
    for (const t of TTP_HINTS) { const o = document.createElement('option'); o.value = t; dl.appendChild(o); }
    document.body.appendChild(dl);
  }

  document.addEventListener('DOMContentLoaded', async () => {
    if (!window.HS || !window.HS.getToken()) return;
    injectTtps();
    try { const m = await window.HS.whoami(); isAdmin = !!(m && m.is_admin); } catch {}
    await loadScenarios();
    await refresh();
    setInterval(refresh, 1500);
  });
})();
