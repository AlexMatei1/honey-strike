// ⌘K / Ctrl+K command palette.
//
// Aggregates static navigation items + live data sources (lessons, recent
// sessions, attack scenarios) into one searchable list. Up/Down to move,
// Enter to fire, Esc to dismiss. Open via Ctrl+K, the topbar trigger, or
// the dock's ⌘ button.

(function () {
  const overlay = document.getElementById('cmdk-overlay');
  const input   = document.getElementById('cmdk-input');
  const list    = document.getElementById('cmdk-list');
  const trigger = document.getElementById('cmdk-trigger');
  const dockBtn = document.getElementById('dock-cmdk');

  if (!overlay || !input || !list) return;

  let items = [];           // full catalogue (loaded once)
  let filtered = [];        // current results
  let sel = 0;
  let loaded = false;

  const NAV_ITEMS = [
    { group: 'Navigate', icon: '🗺', title: 'Live map',          sub: '/',          run: () => go('/') },
    { group: 'Navigate', icon: '📋', title: 'Sessions',          sub: '/sessions',  run: () => go('/sessions') },
    { group: 'Navigate', icon: '📊', title: 'Analytics',         sub: '/analytics', run: () => go('/analytics') },
    { group: 'Navigate', icon: '🎮', title: 'Play hub',          sub: '/play',      run: () => go('/play') },
    { group: 'Navigate', icon: '🗡', title: 'Attack lessons',    sub: '/play/attack', run: () => go('/play/attack') },
    { group: 'Navigate', icon: '🛡', title: 'Defender lessons',  sub: '/play/defend', run: () => go('/play/defend') },
    { group: 'Navigate', icon: '⚔',  title: 'Live defend arena', sub: '/play/defend/arena', run: () => go('/play/defend/arena') },
    { group: 'Navigate', icon: '📡', title: 'War Room',          sub: '/warroom',   run: () => go('/warroom') },
    { group: 'Navigate', icon: '👤', title: 'Profile',           sub: '/profile',   run: () => go('/profile') },
    { group: 'Account',  icon: '⏏',  title: 'Logout',            sub: 'sign out',   run: () => { if (window.HS) window.HS.logout(); } },
  ];

  function go(path) { window.location.href = path; }

  async function loadCatalogue() {
    if (loaded) return;
    loaded = true;
    items = [...NAV_ITEMS];

    // Lessons.
    try {
      const r = await window.HS.apiFetch('/api/lessons');
      if (r.ok) {
        const cat = await r.json();
        for (const l of (cat.attack || [])) {
          items.push({
            group: 'Attack lessons',
            icon: '🗡',
            title: l.title,
            sub: (l.ttps || []).join(' '),
            run: () => go(`/play/attack/${l.id}`),
          });
        }
        for (const l of (cat.defend || [])) {
          items.push({
            group: 'Defender lessons',
            icon: '🛡',
            title: l.title,
            sub: (l.ttps || []).join(' '),
            run: () => go(`/play/defend/${l.id}`),
          });
        }
      }
    } catch {}

    // Attack scenarios — for quick-launch via /api/play/attack.
    try {
      const r = await window.HS.apiFetch('/api/play/scenarios');
      if (r.ok) {
        const sc = await r.json();
        for (const s of (sc.scenarios || [])) {
          items.push({
            group: 'Fire attack',
            icon: '🚀',
            title: `Fire ${s.label}`,
            sub: `target ${s.default_target}`,
            run: () => fireScenario(s.id, s.default_target),
          });
        }
      }
    } catch {}

    // Most recent sessions.
    try {
      const r = await window.HS.apiFetch('/api/sessions?limit=25');
      if (r.ok) {
        const data = await r.json();
        for (const s of (data.items || [])) {
          items.push({
            group: 'Recent sessions',
            icon: severityIcon(s.threat_score),
            title: `${s.service.toUpperCase()}  ${s.src_ip}  score ${s.threat_score}`,
            sub: new Date(s.started_at).toLocaleString(),
            run: () => go(`/sessions/${s.id}`),
          });
        }
      }
    } catch {}
  }

  function severityIcon(score) {
    if (score >= 80) return '🔴';
    if (score >= 50) return '🟠';
    if (score >= 20) return '🟡';
    return '🟢';
  }

  async function fireScenario(scenarioId, target) {
    close();
    if (!window.HS) return;
    try {
      const r = await window.HS.apiFetch('/api/play/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId, target, intensity: 'burst' }),
      });
      if (r.ok && window.HSGame) window.HSGame.flash(`🚀 Fired ${scenarioId}`);
      else if (window.HSGame) window.HSGame.woops(`launch failed (HTTP ${r.status})`);
    } catch (e) {
      if (window.HSGame) window.HSGame.woops(`launch error: ${e.message || e}`);
    }
  }

  function fuzzyMatch(q, str) {
    if (!q) return 0;
    const s = str.toLowerCase();
    const ql = q.toLowerCase();
    if (s.includes(ql)) return 100 - s.indexOf(ql);
    // simple subsequence match
    let i = 0, score = 0;
    for (const c of s) {
      if (c === ql[i]) { score += 1; i += 1; if (i >= ql.length) break; }
    }
    return i >= ql.length ? score : 0;
  }

  function filter(q) {
    if (!q.trim()) return items.slice(0, 30);
    return items
      .map(it => ({ it, s: fuzzyMatch(q, it.title + ' ' + (it.sub || '') + ' ' + it.group) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 30)
      .map(x => x.it);
  }

  function render() {
    list.innerHTML = '';
    if (!filtered.length) {
      list.innerHTML = '<li class="cmdk-empty">No matches.</li>';
      return;
    }
    let lastGroup = null;
    filtered.forEach((it, i) => {
      if (it.group !== lastGroup) {
        const t = document.createElement('li');
        t.className = 'cmdk-group-title';
        t.textContent = it.group;
        list.appendChild(t);
        lastGroup = it.group;
      }
      const li = document.createElement('li');
      li.className = 'cmdk-item' + (i === sel ? ' sel' : '');
      li.dataset.idx = String(i);
      li.innerHTML = `<span class="cmdk-icon">${it.icon || '•'}</span><span class="cmdk-title">${escapeHtml(it.title)}</span><span class="cmdk-sub">${escapeHtml(it.sub || '')}</span>`;
      li.addEventListener('mousemove', () => { sel = i; paintSelected(); });
      li.addEventListener('click', () => fire(i));
      list.appendChild(li);
    });
  }

  function paintSelected() {
    list.querySelectorAll('.cmdk-item').forEach((el) => {
      el.classList.toggle('sel', Number(el.dataset.idx) === sel);
    });
    const cur = list.querySelector('.cmdk-item.sel');
    if (cur) cur.scrollIntoView({ block: 'nearest' });
  }

  function fire(i) {
    const it = filtered[i];
    if (!it) return;
    close();
    it.run();
  }

  function escapeHtml(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  async function open() {
    if (!loaded) await loadCatalogue();
    sel = 0;
    input.value = '';
    filtered = filter('');
    render();
    overlay.hidden = false;
    setTimeout(() => input.focus(), 30);
  }
  function close() { overlay.hidden = true; }

  input.addEventListener('input', () => {
    sel = 0;
    filtered = filter(input.value);
    render();
  });

  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'ArrowDown')  { ev.preventDefault(); sel = Math.min(filtered.length - 1, sel + 1); paintSelected(); }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); sel = Math.max(0, sel - 1); paintSelected(); }
    else if (ev.key === 'Enter')   { ev.preventDefault(); fire(sel); }
    else if (ev.key === 'Escape')  { ev.preventDefault(); close(); }
  });

  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  if (trigger) trigger.addEventListener('click', open);
  if (dockBtn) dockBtn.addEventListener('click', open);

  document.addEventListener('keydown', (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && (ev.key === 'k' || ev.key === 'K')) {
      ev.preventDefault();
      if (overlay.hidden) open(); else close();
    }
  });
})();
