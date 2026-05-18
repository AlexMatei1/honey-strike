// /warroom — full-screen takeover view.
//
// Big stat tiles + Leaflet world map + scrolling attack feed + top
// attackers + top TTPs. Designed for a wall-mounted screen during demos
// and the multiplayer game finale.

(function () {
  const TICKER_LIMIT = 25;
  const MARKER_TTL_MS = 120_000;
  const markers = new Map();        // session_id -> { marker, addedAt }
  let blockedCount = 0;             // tracked client-side via WS sessions + manual refresh

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

  function initMap() {
    const map = L.map('war-map', {
      preferCanvas: true, zoomControl: false, attributionControl: false,
    }).setView([25, 10], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 8, minZoom: 2, subdomains: 'abcd',
    }).addTo(map);
    return map;
  }

  function addMarker(map, msg) {
    if (msg.lat == null || msg.lon == null) return;
    const sev = severityClass(msg.threat_score);
    const icon = L.divIcon({
      className: '',
      html: `<div class="attack-marker ${sev}"></div>`,
      iconSize: [16, 16], iconAnchor: [8, 8],
    });
    const marker = L.marker([msg.lat, msg.lon], { icon }).addTo(map);
    marker.bindPopup(
      `<strong>${msg.service.toUpperCase()}</strong> · ${msg.src_ip}<br>` +
      `score ${msg.threat_score} (${msg.severity})`,
    );
    markers.set(msg.session_id, { marker, addedAt: Date.now() });
  }

  function pruneMarkers(map) {
    const now = Date.now();
    for (const [sid, e] of markers) {
      if (now - e.addedAt > MARKER_TTL_MS) {
        map.removeLayer(e.marker);
        markers.delete(sid);
      }
    }
  }

  function pushTicker(msg) {
    const ol = document.getElementById('war-ticker-list');
    const li = document.createElement('li');
    li.className = `tick sev-${severityClass(msg.threat_score)}`;
    const ttps = msg.ttp_count ? ` · ${msg.ttp_count} TTPs` : '';
    li.innerHTML = `
      <span class="tick-time">${fmtTime(msg.started_at)}</span>
      <span class="tick-sev">${severityClass(msg.threat_score).toUpperCase()}</span>
      <span class="tick-score">${msg.threat_score}</span>
      <span class="tick-svc">${msg.service}</span>
      <code>${msg.src_ip}</code>
      <span class="muted">${msg.country_iso || '??'}${ttps}</span>
    `;
    ol.insertBefore(li, ol.firstChild);
    while (ol.children.length > TICKER_LIMIT) ol.removeChild(ol.lastChild);
  }

  function setStat(key, value) {
    const el = document.querySelector(`[data-key="${key}"]`);
    if (el) el.textContent = value;
  }

  async function refreshStats() {
    try {
      const r = await window.HS.apiFetch('/api/stats/overview?days=1');
      if (!r.ok) return;
      const d = await r.json();
      setStat('total_sessions', d.total_sessions);
      setStat('unique_ips', d.unique_ips);
      setStat('avg_threat_score', (d.avg_threat_score || 0).toFixed(1));
      setStat('critical', (d.severity_breakdown || {}).critical || 0);
      setStat('alerts', d.alerts_dispatched ?? '—');
      setStat('blocked', blockedCount);
    } catch (e) { /* ignore */ }
  }

  async function refreshTopAttackers() {
    try {
      const r = await window.HS.apiFetch('/api/sessions?limit=200');
      if (!r.ok) return;
      const data = await r.json();
      const agg = new Map();
      for (const s of data.items || []) {
        const key = s.src_ip;
        const cur = agg.get(key) || { ip: key, sessions: 0, max_score: 0 };
        cur.sessions += 1;
        cur.max_score = Math.max(cur.max_score, s.threat_score);
        agg.set(key, cur);
      }
      const rows = [...agg.values()]
        .sort((a, b) => b.max_score - a.max_score || b.sessions - a.sessions)
        .slice(0, 8);
      const tb = document.getElementById('war-top-attackers');
      tb.innerHTML = rows.length
        ? rows.map(r => `
            <tr>
              <td><code>${r.ip}</code></td>
              <td>${r.sessions}</td>
              <td><span class="score-pill score-${severityClass(r.max_score)}">${r.max_score}</span></td>
            </tr>`).join('')
        : '<tr><td colspan="3" class="muted">no traffic in window</td></tr>';
    } catch (e) { /* ignore */ }
  }

  async function refreshTopTtps() {
    try {
      const r = await window.HS.apiFetch('/api/stats/ttps?days=1');
      if (!r.ok) return;
      const list = await r.json();
      const tb = document.getElementById('war-top-ttps');
      tb.innerHTML = list.length
        ? list.slice(0, 8).map(t => `
            <tr>
              <td><code>${t.technique_id}</code></td>
              <td>${t.technique_name || ''}</td>
              <td>${t.count}</td>
            </tr>`).join('')
        : '<tr><td colspan="3" class="muted">no TTPs in window</td></tr>';
    } catch (e) { /* ignore */ }
  }

  function connectWebSocket(map) {
    const token = window.HS.getToken();
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${window.location.host}/api/ws/live?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);
    ws.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === 'session') {
        addMarker(map, msg);
        pushTicker(msg);
      }
    });
    ws.addEventListener('close', () => setTimeout(() => connectWebSocket(map), 3000));
  }

  function waitForLeaflet(cb, tries = 50) {
    if (window.L && typeof window.L.map === 'function') return cb();
    if (tries <= 0) return;
    setTimeout(() => waitForLeaflet(cb, tries - 1), 100);
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    waitForLeaflet(() => {
      const map = initMap();
      connectWebSocket(map);
      setInterval(() => pruneMarkers(map), 15_000);
    });
    refreshStats();
    refreshTopAttackers();
    refreshTopTtps();
    setInterval(refreshStats, 15_000);
    setInterval(refreshTopAttackers, 30_000);
    setInterval(refreshTopTtps, 30_000);
  });
})();
