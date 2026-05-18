// Ambient threat-level border around the viewport.
//
// Polls /api/stats/overview every 30 s and paints the --threat-color CSS
// variable based on the current critical-session count + average score.
// Also opens /api/ws/live and adds a quick `threat-pulse` flash whenever a
// new critical session arrives — gives the operator a peripheral signal
// without yanking focus.

(function () {
  const COLORS = {
    low:      'var(--low)',
    medium:   'var(--medium)',
    high:     'var(--high)',
    critical: 'var(--critical)',
  };

  function setLevel(level) {
    document.documentElement.style.setProperty('--threat-color', COLORS[level] || COLORS.low);
  }

  function deriveLevel(d) {
    const critical = (d.severity_breakdown || {}).critical || 0;
    const high     = (d.severity_breakdown || {}).high     || 0;
    const avg      = d.avg_threat_score || 0;
    if (critical > 0)         return 'critical';
    if (high > 0 || avg >= 50) return 'high';
    if (avg >= 20)             return 'medium';
    return 'low';
  }

  async function poll() {
    try {
      const r = await window.HS.apiFetch('/api/stats/overview?days=1');
      if (!r.ok) return;
      const data = await r.json();
      setLevel(deriveLevel(data));
    } catch (_) { /* ignore */ }
  }

  function pulse() {
    document.body.classList.remove('threat-pulse');
    void document.body.offsetWidth;
    document.body.classList.add('threat-pulse');
  }

  function connectWebSocket() {
    const token = window.HS && window.HS.getToken();
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${window.location.host}/api/ws/live?token=${encodeURIComponent(token)}`;
    let ws;
    try { ws = new WebSocket(url); }
    catch { return; }
    ws.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type !== 'session') return;
      if ((msg.severity || '').toLowerCase() === 'critical' || (msg.threat_score || 0) >= 80) {
        setLevel('critical');
        pulse();
      }
    });
    ws.addEventListener('close', () => setTimeout(connectWebSocket, 6000));
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    poll();
    setInterval(poll, 30_000);
    connectWebSocket();
  });
})();
