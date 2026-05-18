// /play/defend — live defender arena.
//
// Subscribes to /api/ws/live. Each incoming session becomes a card with a
// "Label this TTP" input (autocomplete from a small MITRE list) and a
// "🚫 Block" button. Correct labels also fire a block via /api/defender/label.

(function () {
  const feed = document.getElementById('defend-feed');
  const blockedList = document.getElementById('blocked-list');
  const labelsLog = document.getElementById('labels-log');

  const cards = new Map();          // session_id -> card element
  const blocked = new Map();        // ip -> { until, li }
  const MAX_CARDS = 25;

  // Small fixed pool of TTPs that show up most often — enough for the
  // arcade-style label box without dragging in the whole MITRE catalogue.
  const TTP_HINTS = [
    'T1110.001', 'T1110.004',
    'T1190', 'T1083', 'T1592', 'T1595', 'T1595.001',
    'T1078', 'T1059', 'T1496',
  ];

  function severityClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleTimeString('en-GB', { hour12: false });
  }

  function emptyFeed() {
    return feed.querySelector('p.muted');
  }

  function makeCard(msg) {
    const card = document.createElement('article');
    card.className = `defend-card sev-${severityClass(msg.threat_score)}`;
    card.dataset.sessionId = msg.session_id;
    card.dataset.srcIp = msg.src_ip;
    card.innerHTML = `
      <header class="defend-card-head">
        <span class="score-pill score-${severityClass(msg.threat_score)}">${msg.threat_score}</span>
        <span class="service-chip">${msg.service.toUpperCase()}</span>
        <code class="src-ip">${msg.src_ip}</code>
        <span class="muted">${msg.country_iso || '??'} · ${fmtTime(msg.started_at)}</span>
        <a class="muted" href="/sessions/${msg.session_id}" target="_blank">open ↗</a>
        <a class="muted" href="/sessions/${msg.session_id}/replay" target="_blank">replay ▶</a>
      </header>
      <div class="defend-card-body">
        <form class="label-form">
          <input list="ttp-hints" name="ttp" placeholder="T1110.001"
                 autocomplete="off" spellcheck="false" maxlength="16" required>
          <button type="submit">Label</button>
          <button type="button" class="block-btn" title="Block this source IP for 5 min">🚫 Block</button>
          <span class="label-result muted">—</span>
        </form>
      </div>
    `;

    card.querySelector('.label-form').addEventListener('submit', (e) => {
      e.preventDefault();
      submitLabel(card, msg);
    });
    card.querySelector('.block-btn').addEventListener('click', () => {
      manualBlock(msg.src_ip, card);
    });
    return card;
  }

  function pushCard(msg) {
    const placeholder = emptyFeed();
    if (placeholder) placeholder.remove();
    if (cards.has(msg.session_id)) return;
    const card = makeCard(msg);
    feed.insertBefore(card, feed.firstChild);
    cards.set(msg.session_id, card);
    while (feed.children.length > MAX_CARDS) {
      const removed = feed.lastChild;
      cards.delete(removed.dataset.sessionId);
      feed.removeChild(removed);
    }
  }

  async function submitLabel(card, msg) {
    const form = card.querySelector('.label-form');
    const input = form.querySelector('input[name="ttp"]');
    const result = card.querySelector('.label-result');
    const ttp = (input.value || '').trim().toUpperCase();
    if (!ttp) return;
    result.textContent = 'submitting…';
    result.className = 'label-result muted';
    try {
      const r = await window.HS.apiFetch('/api/defender/label', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: msg.session_id,
          technique_id: ttp,
          block: true,
          ttl_seconds: 300,
        }),
      });
      if (!r.ok) {
        result.textContent = `label failed: HTTP ${r.status}`;
        result.className = 'label-result error';
        return;
      }
      const data = await r.json();
      if (data.correct) {
        result.textContent = `✓ correct — actual: ${data.actual_ttps.join(', ')}`;
        result.className = 'label-result ok';
        card.classList.add('labelled-ok');
        if (data.blocked_ip) {
          recordBlock(data.blocked_ip, data.ttl_seconds || 300);
        }
        logAction(`✓ ${ttp} on ${msg.src_ip} — ${data.blocked_ip ? 'blocked' : 'label only'}`);
        if (window.HSGame) window.HSGame.onCorrectLabel();
      } else {
        result.textContent = `✗ wrong — actual: ${data.actual_ttps.join(', ') || 'none'}`;
        result.className = 'label-result bad';
        logAction(`✗ ${ttp} on ${msg.src_ip} (actual ${data.actual_ttps.join(',') || 'none'})`);
        if (window.HSGame) window.HSGame.onWrongLabel();
      }
    } catch (e) {
      result.textContent = `error: ${e.message || e}`;
      result.className = 'label-result error';
    }
  }

  async function manualBlock(ip, card) {
    const result = card.querySelector('.label-result');
    result.textContent = 'blocking…';
    result.className = 'label-result muted';
    try {
      const r = await window.HS.apiFetch('/api/defender/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, ttl_seconds: 300, reason: 'manual-from-defend-arena' }),
      });
      if (!r.ok) {
        result.textContent = `block failed: HTTP ${r.status}`;
        result.className = 'label-result error';
        return;
      }
      const data = await r.json();
      result.textContent = `🚫 blocked ${data.ip} for ${data.ttl_seconds}s`;
      result.className = 'label-result ok';
      recordBlock(data.ip, data.ttl_seconds);
      logAction(`🚫 manual block ${data.ip}`);
    } catch (e) {
      result.textContent = `error: ${e.message || e}`;
      result.className = 'label-result error';
    }
  }

  function recordBlock(ip, ttlSeconds) {
    if (blocked.has(ip)) {
      const entry = blocked.get(ip);
      entry.until = Date.now() + ttlSeconds * 1000;
      return;
    }
    if (blockedList.firstElementChild && blockedList.firstElementChild.matches('li.muted')) {
      blockedList.innerHTML = '';
    }
    const li = document.createElement('li');
    li.innerHTML = `<code>${ip}</code> <span class="countdown">${ttlSeconds}s</span>
      <button type="button" class="unblock-btn" title="Unblock now">×</button>`;
    li.querySelector('.unblock-btn').addEventListener('click', () => unblock(ip));
    blockedList.appendChild(li);
    blocked.set(ip, { until: Date.now() + ttlSeconds * 1000, li });
  }

  async function unblock(ip) {
    try {
      await window.HS.apiFetch(`/api/defender/block/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    } catch (e) { /* ignore */ }
    dropBlock(ip);
    logAction(`unblocked ${ip}`);
  }

  function dropBlock(ip) {
    const entry = blocked.get(ip);
    if (!entry) return;
    entry.li.remove();
    blocked.delete(ip);
    if (!blockedList.children.length) {
      blockedList.innerHTML = '<li class="muted">none</li>';
    }
  }

  function tickBlocks() {
    const now = Date.now();
    for (const [ip, entry] of blocked) {
      const remain = Math.max(0, Math.round((entry.until - now) / 1000));
      const span = entry.li.querySelector('.countdown');
      if (span) span.textContent = `${remain}s`;
      if (remain <= 0) dropBlock(ip);
    }
  }

  function logAction(line) {
    if (labelsLog.firstElementChild && labelsLog.firstElementChild.matches('li.muted')) {
      labelsLog.innerHTML = '';
    }
    const li = document.createElement('li');
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
    li.textContent = `[${ts}] ${line}`;
    labelsLog.insertBefore(li, labelsLog.firstChild);
    while (labelsLog.children.length > 30) {
      labelsLog.removeChild(labelsLog.lastChild);
    }
  }

  function injectDatalist() {
    if (document.getElementById('ttp-hints')) return;
    const dl = document.createElement('datalist');
    dl.id = 'ttp-hints';
    for (const id of TTP_HINTS) {
      const o = document.createElement('option');
      o.value = id;
      dl.appendChild(o);
    }
    document.body.appendChild(dl);
  }

  function connectWebSocket() {
    const token = window.HS.getToken();
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${window.location.host}/api/ws/live?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);
    ws.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === 'session') pushCard(msg);
    });
    ws.addEventListener('close', () => setTimeout(connectWebSocket, 3000));
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    injectDatalist();
    connectWebSocket();
    setInterval(tickBlocks, 1000);
  });
})();
