// /play/duel — member-vs-member consensual PvP.
//
// Polls /api/duels/mine + /inbox every 2s. When a duel is active, renders the
// arena role-aware: the attacker gets fire buttons, the defender gets the
// incoming-wave list with label inputs. Both see the timer + live scores.

(function () {
  const arena = document.getElementById('duel-arena');
  const inboxEl = document.getElementById('duel-inbox');
  const oppSel = document.getElementById('opponent');
  const challengeForm = document.getElementById('challenge-form');
  const challengeMsg = document.getElementById('challenge-msg');
  const lbEl = document.getElementById('duel-leaderboard');

  let scenarios = [];
  let activeDuelId = null;
  let pollTimer = null;

  const TTP_HINTS = ['T1110.001', 'T1110.004', 'T1190', 'T1083', 'T1592', 'T1595.001', 'T1078'];

  async function api(path, opts) {
    return window.HS.apiFetch(path, opts);
  }
  function esc(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ---- challenge setup -------------------------------------------------
  async function loadOpponents() {
    const r = await api('/api/duels/opponents');
    if (!r.ok) return;
    const list = await r.json();
    oppSel.innerHTML = '';
    if (!list.length) {
      oppSel.innerHTML = '<option value="">(no other players yet)</option>';
      return;
    }
    for (const o of list) {
      const opt = document.createElement('option');
      opt.value = o.username;
      opt.textContent = `${o.username} (${o.role === 'admin' ? 'Lead' : 'Analyst'})`;
      oppSel.appendChild(opt);
    }
  }

  async function loadScenarios() {
    const r = await api('/api/duels/scenarios');
    if (r.ok) scenarios = await r.json();
  }

  challengeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const opponent = oppSel.value;
    if (!opponent) return;
    challengeMsg.textContent = 'Sending…';
    const r = await api('/api/duels/challenge', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ opponent, duration_seconds: Number(document.getElementById('duration').value) }),
    });
    if (!r.ok) {
      let m = `HTTP ${r.status}`;
      try { const j = await r.json(); if (j.detail) m = j.detail; } catch {}
      challengeMsg.textContent = '✗ ' + m;
      challengeMsg.className = 'error';
      return;
    }
    challengeMsg.textContent = `✓ Challenge sent to ${opponent}. Waiting for them to accept…`;
    challengeMsg.className = 'ok';
    refresh();
  });

  // ---- inbox -----------------------------------------------------------
  function renderInbox(duels) {
    const pending = duels.filter(d => d.status === 'pending' && d.your_role === 'defender');
    if (!pending.length) { inboxEl.innerHTML = '<li class="muted">none right now</li>'; return; }
    inboxEl.innerHTML = '';
    for (const d of pending) {
      const li = document.createElement('li');
      li.innerHTML = `<strong>${esc(d.attacker)}</strong> challenged you
        (${Math.round(d.duration_seconds / 60)} min)
        <button data-act="accept" data-id="${d.id}">Accept</button>
        <button data-act="decline" data-id="${d.id}" class="muted">Decline</button>`;
      inboxEl.appendChild(li);
    }
    inboxEl.querySelectorAll('button[data-act]').forEach(b => {
      b.addEventListener('click', () => respond(b.dataset.id, b.dataset.act));
    });
  }

  async function respond(id, act) {
    const r = await api(`/api/duels/${id}/${act}`, { method: 'POST' });
    if (r.ok && act === 'accept') activeDuelId = id;
    refresh();
  }

  // ---- arena -----------------------------------------------------------
  function renderArena(d) {
    if (!d || (d.status !== 'active' && d.status !== 'finished')) {
      arena.hidden = true;
      arena.innerHTML = '';
      return;
    }
    arena.hidden = false;
    const youAtk = d.your_role === 'attacker';
    const opp = youAtk ? d.defender : d.attacker;
    const mins = Math.floor(d.seconds_left / 60), secs = d.seconds_left % 60;
    const timer = d.status === 'finished' ? 'FINISHED'
      : `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;

    let body = `
      <div class="duel-head">
        <div class="duel-vs">
          <span class="${youAtk ? 'you' : ''}">🗡 ${esc(d.attacker)}</span>
          <span class="duel-score">${d.attacker_score}</span>
          <span class="duel-dash">vs</span>
          <span class="duel-score">${d.defender_score}</span>
          <span class="${!youAtk ? 'you' : ''}">🛡 ${esc(d.defender)}</span>
        </div>
        <div class="duel-timer ${d.seconds_left <= 30 && d.status === 'active' ? 'low' : ''}">${timer}</div>
      </div>`;

    if (d.status === 'finished') {
      const win = d.attacker_score === d.defender_score ? 'Draw!'
        : (d.attacker_score > d.defender_score ? `${esc(d.attacker)} (attacker) wins!` : `${esc(d.defender)} (defender) wins!`);
      body += `<p class="duel-result">🏁 ${win}</p>`;
    } else if (youAtk) {
      body += `<p class="muted">Fire waves at ${esc(opp)}. Each wave they fail to label in time scores you 10.</p>
        <div class="duel-fire">` +
        scenarios.map(s => `<button data-fire="${s.id}">🚀 ${esc(s.label)}</button>`).join('') +
        `</div>`;
    } else {
      body += `<p class="muted">Incoming waves from ${esc(opp)} — label each technique to block it (10 pts each).</p>`;
    }

    // Wave list (both sides see it; defender labels open ones).
    body += '<ol class="duel-waves">';
    for (const w of (d.waves || [])) {
      let right = '';
      if (w.resolved) {
        right = w.correct ? `<span class="ok">✓ blocked (${esc((w.expected_ttps || []).join(', '))})</span>`
                          : `<span class="bad">✗ ${esc(w.labeled_ttp || '')}</span>`;
      } else if (d.status === 'finished') {
        right = `<span class="bad">⚠ got through (${esc((w.expected_ttps || []).join(', '))})</span>`;
      } else if (!youAtk) {
        right = `<input list="duel-ttps" data-wave="${w.id}" placeholder="T1110.001" maxlength="16">
                 <button data-label="${w.id}">Block</button>
                 ${w.labeled_ttp ? `<span class="muted">last: ${esc(w.labeled_ttp)} ✗</span>` : ''}`;
      } else {
        right = '<span class="muted">waiting for defender…</span>';
      }
      body += `<li><span class="wave-name">🌊 ${esc(w.label)}</span> ${right}</li>`;
    }
    body += '</ol>';

    if (d.status === 'active') {
      body += `<div class="duel-actions"><button id="duel-finish" class="muted">End duel now</button></div>`;
    }

    arena.innerHTML = body;

    arena.querySelectorAll('button[data-fire]').forEach(b => {
      b.addEventListener('click', () => fire(d.id, b.dataset.fire, b));
    });
    arena.querySelectorAll('button[data-label]').forEach(b => {
      b.addEventListener('click', () => labelWave(d.id, b.dataset.label));
    });
    const fin = document.getElementById('duel-finish');
    if (fin) fin.addEventListener('click', () => finishDuel(d.id));
  }

  async function fire(id, scenario, btn) {
    if (btn) btn.disabled = true;
    const r = await api(`/api/duels/${id}/fire`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
    if (!r.ok && window.HSGame) {
      let m = `HTTP ${r.status}`; try { const j = await r.json(); if (j.detail) m = j.detail; } catch {}
      window.HSGame.woops(m);
    }
    setTimeout(() => { if (btn) btn.disabled = false; }, 800);
    refresh();
  }

  async function labelWave(id, waveId) {
    const input = arena.querySelector(`input[data-wave="${waveId}"]`);
    const ttp = (input && input.value || '').trim();
    if (!ttp) return;
    const r = await api(`/api/duels/${id}/label`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ wave_id: waveId, technique_id: ttp }),
    });
    if (r.ok) {
      const out = await r.json();
      if (window.HSGame) {
        if (out.correct) window.HSGame.flash('✓ Blocked the wave! +10');
        else window.HSGame.woops('✗ Wrong technique — try again');
      }
    }
    refresh();
  }

  async function finishDuel(id) {
    await api(`/api/duels/${id}/finish`, { method: 'POST' });
    refresh();
  }

  // ---- leaderboard -----------------------------------------------------
  async function loadLeaderboard() {
    const r = await api('/api/duels/leaderboard');
    if (!r.ok) return;
    const rows = await r.json();
    if (!rows.length) { lbEl.innerHTML = '<tr><td colspan="4" class="muted">No duels played yet.</td></tr>'; return; }
    lbEl.innerHTML = rows.map((r, i) =>
      `<tr><td>${i === 0 ? '🥇 ' : ''}${esc(r.username)}</td><td>${r.duels_won}</td><td>${r.duels_played}</td><td>${r.xp}</td></tr>`
    ).join('');
  }

  // ---- poll loop -------------------------------------------------------
  async function refresh() {
    try {
      const r = await api('/api/duels/mine');
      if (!r.ok) return;
      const duels = await r.json();
      renderInbox(duels);
      // Pick an active duel to show; else the most recent pending I'm in.
      let active = duels.find(d => d.status === 'active');
      if (!active) active = duels.find(d => d.status === 'pending' && d.your_role === 'attacker');
      if (active) { activeDuelId = active.id; renderArena(active); }
      else { arena.hidden = true; arena.innerHTML = ''; }
    } catch (_) { /* ignore */ }
  }

  function injectTtpList() {
    if (document.getElementById('duel-ttps')) return;
    const dl = document.createElement('datalist');
    dl.id = 'duel-ttps';
    for (const t of TTP_HINTS) { const o = document.createElement('option'); o.value = t; dl.appendChild(o); }
    document.body.appendChild(dl);
  }

  document.addEventListener('DOMContentLoaded', async () => {
    if (!window.HS || !window.HS.getToken()) return;
    injectTtpList();
    await Promise.all([loadOpponents(), loadScenarios()]);
    await refresh();
    await loadLeaderboard();
    pollTimer = setInterval(() => { refresh(); }, 2000);
    setInterval(loadLeaderboard, 15000);
  });
})();
