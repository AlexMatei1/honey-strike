// Session detail — loads /api/sessions/{id} and renders all the panels.

(function () {
  function fmt(value) {
    if (value === null || value === undefined || value === '') return '—';
    return value;
  }

  function fillKV(container, mapping) {
    container.querySelectorAll('[data-key]').forEach((td) => {
      const key = td.dataset.key;
      td.textContent = fmt(mapping[key]);
    });
  }

  async function loadDetail() {
    const sid = document.getElementById('session-id').textContent.trim();
    const status = document.getElementById('detail-status');
    const grid = document.getElementById('detail-grid');
    try {
      const r = await window.HS.apiFetch(`/api/sessions/${sid}`);
      if (!r.ok) {
        status.textContent = r.status === 404 ? 'Session not found.' : `Error ${r.status}`;
        return;
      }
      const data = await r.json();
      const fp = data.fingerprint || {};
      fillKV(grid, {
        src_ip: data.src_ip,
        country: fp.country_iso ? `${fp.country_iso}${fp.country_name ? ' — ' + fp.country_name : ''}` : null,
        asn: fp.asn ? `AS${fp.asn}${fp.org ? ' (' + fp.org + ')' : ''}` : null,
        org: fp.org,
        abuse_score: fp.abuse_score != null ? `${fp.abuse_score}/100` : null,
        service: data.service,
        state: data.state,
        threat_score: `${data.threat_score}/100`,
        severity: data.severity,
        started_at: data.started_at,
        duration_ms: data.duration_ms,
        event_count: data.event_count,
      });

      const ts = document.getElementById('tool-signatures');
      ts.innerHTML = '';
      (fp.tool_signatures || []).forEach((sig) => {
        const li = document.createElement('li');
        li.textContent = `${sig.name} — confidence ${Number(sig.confidence).toFixed(2)}`;
        ts.appendChild(li);
      });
      if (!ts.children.length) ts.innerHTML = '<li class="muted">No tool signatures.</li>';

      const ttpBody = document.getElementById('ttp-tbody');
      ttpBody.innerHTML = '';
      (data.ttps || []).forEach((t) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><code>${t.technique_id}</code></td><td>${t.technique_name}</td><td>${t.tactic}</td><td>${Number(t.confidence).toFixed(2)}</td>`;
        ttpBody.appendChild(tr);
      });
      if (!ttpBody.children.length) {
        ttpBody.innerHTML = '<tr><td colspan="4" class="muted">No MITRE attributions.</td></tr>';
      }

      const evBody = document.getElementById('events-tbody');
      evBody.innerHTML = '';
      ((data.events || {}).preview || []).forEach((e) => {
        const tr = document.createElement('tr');
        const payload = JSON.stringify(e.payload).slice(0, 300);
        tr.innerHTML = `<td>${new Date(e.timestamp).toLocaleTimeString('en-GB', {hour12: false})}</td><td>${e.event_type}</td><td><code>${payload}</code></td>`;
        evBody.appendChild(tr);
      });
      if (!evBody.children.length) {
        evBody.innerHTML = '<tr><td colspan="3" class="muted">No events.</td></tr>';
      }

      const alerts = document.getElementById('alerts-list');
      alerts.innerHTML = '';
      (data.alerts || []).forEach((a) => {
        const li = document.createElement('li');
        li.textContent = `${a.channel} — ${a.severity} (score ${a.threat_score}) at ${a.dispatched_at}`;
        alerts.appendChild(li);
      });
      if (!alerts.children.length) alerts.innerHTML = '<li class="muted">No alerts dispatched.</li>';

      status.hidden = true;
      grid.hidden = false;
      wireBlockButton(data.src_ip);
    } catch (e) {
      status.textContent = 'Failed to load session: ' + e.message;
    }
  }

  function wireBlockButton(srcIp) {
    const btn = document.getElementById('block-src-btn');
    const result = document.getElementById('block-result');
    if (!btn || !srcIp) return;
    btn.hidden = false;
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      result.textContent = 'Blocking…';
      result.className = 'muted';
      try {
        const r = await window.HS.apiFetch('/api/defender/block', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: srcIp, ttl_seconds: 300, reason: 'manual-from-session-detail' }),
        });
        if (!r.ok) {
          result.textContent = `Block failed (HTTP ${r.status})`;
          result.className = 'error';
          btn.disabled = false;
          return;
        }
        const data = await r.json();
        result.textContent = `🚫 Blocked ${data.ip} for ${data.ttl_seconds}s.`;
        result.className = 'ok';
        if (window.HSGame) window.HSGame.onBlock();
      } catch (e) {
        result.textContent = `Block error: ${e.message || e}`;
        result.className = 'error';
        btn.disabled = false;
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    loadDetail();
  });
})();
