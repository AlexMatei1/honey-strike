// Live attack map + session sidebar.
//
// Loads an overview snapshot from /api/stats/overview, opens a WS to
// /api/ws/live for streamed updates, plots markers on Leaflet, and keeps a
// rolling "most recent" sessions table in the sidebar.

(function () {
  const SIDEBAR_LIMIT = 30;
  const MARKER_TTL_MS = 90_000;

  const sidebarRows = new Map();   // session_id -> tr
  const markers = new Map();        // session_id -> {marker, addedAt}

  function severityClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleTimeString('en-GB', { hour12: false });
  }

  async function loadOverview() {
    try {
      const r = await window.HS.apiFetch('/api/stats/overview?days=1');
      if (!r.ok) return;
      const data = await r.json();
      const overview = document.getElementById('overview');
      overview.querySelector('[data-key="total_sessions"]').textContent = data.total_sessions;
      overview.querySelector('[data-key="unique_ips"]').textContent = data.unique_ips;
      overview.querySelector('[data-key="avg_threat_score"]').textContent = data.avg_threat_score.toFixed(1);
      overview.querySelector('[data-key="severity_critical"]').textContent = (data.severity_breakdown || {}).critical || 0;
    } catch (e) {
      console.warn('overview load failed', e);
    }
  }

  function initMap() {
    const map = L.map('map', { preferCanvas: true }).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '© OpenStreetMap, © CartoDB',
      maxZoom: 8,
      minZoom: 2,
      subdomains: 'abcd',
    }).addTo(map);
    return map;
  }

  function addSidebarRow(session) {
    const tbody = document.getElementById('sessions-tbody');
    const tr = document.createElement('tr');
    tr.dataset.sessionId = session.session_id;
    tr.addEventListener('click', () => {
      window.location.href = `/sessions/${session.session_id}`;
    });
    tr.innerHTML = `
      <td>${fmtTime(session.started_at)}</td>
      <td>${session.service}</td>
      <td><code>${session.src_ip}</code></td>
      <td><span class="score-pill score-${severityClass(session.threat_score)}">${session.threat_score}</span></td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
    sidebarRows.set(session.session_id, tr);

    while (tbody.children.length > SIDEBAR_LIMIT) {
      const removed = tbody.lastChild;
      const sid = removed.dataset.sessionId;
      sidebarRows.delete(sid);
      tbody.removeChild(removed);
    }
  }

  function addMarker(map, session) {
    if (session.lat == null || session.lon == null) return;
    const sev = severityClass(session.threat_score);
    const icon = L.divIcon({
      className: '',
      html: `<div class="attack-marker ${sev}" style="width:14px;height:14px;color:var(--${sev});"></div>`,
      iconSize: [14, 14],
      iconAnchor: [7, 7],
    });
    const marker = L.marker([session.lat, session.lon], { icon }).addTo(map);
    marker.bindPopup(
      `<strong>${session.service.toUpperCase()}</strong> &middot; ${session.src_ip}<br>` +
      `Score <strong>${session.threat_score}</strong> (${session.severity})<br>` +
      `<a href="/sessions/${session.session_id}">Open detail &rarr;</a>`
    );
    markers.set(session.session_id, { marker, addedAt: Date.now() });
  }

  function pruneMarkers(map) {
    const now = Date.now();
    for (const [sid, entry] of markers) {
      if (now - entry.addedAt > MARKER_TTL_MS) {
        map.removeLayer(entry.marker);
        markers.delete(sid);
      }
    }
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
        addSidebarRow(msg);
        addMarker(map, msg);
      }
    });

    ws.addEventListener('close', () => {
      // Naive reconnect with backoff.
      setTimeout(() => connectWebSocket(map), 3000);
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    loadOverview();
    setInterval(loadOverview, 30_000);
    const map = initMap();
    setInterval(() => pruneMarkers(map), 10_000);
    connectWebSocket(map);
  });
})();
