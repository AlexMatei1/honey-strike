// Analytics page — charts driven by the existing /api/stats/* endpoints.
//
// Uses Chart.js loaded from CDN. We register one chart per canvas, then on
// each "Refresh" we tear down the prior instances before constructing the
// new ones so colour palettes and tooltips stay consistent.

(function () {
  const charts = {};

  const palette = {
    low:      'rgba(95, 184, 120, 0.85)',
    medium:   'rgba(210, 153, 34, 0.85)',
    high:     'rgba(240, 136, 62, 0.85)',
    critical: 'rgba(248, 81, 73, 0.85)',
    bar:      'rgba(88, 166, 255, 0.85)',
    line:     'rgba(88, 166, 255, 0.95)',
    fill:     'rgba(88, 166, 255, 0.15)',
    services: {
      ssh:  'rgba(95, 184, 120, 0.85)',
      http: 'rgba(88, 166, 255, 0.85)',
      ftp:  'rgba(210, 153, 34, 0.85)',
      rdp:  'rgba(248, 81, 73, 0.85)',
    },
  };

  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = 'rgba(139, 148, 158, 0.15)';
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;

  function destroy(id) {
    if (charts[id]) {
      charts[id].destroy();
      delete charts[id];
    }
  }

  function fmtBucket(iso, bucket) {
    const d = new Date(iso);
    if (bucket === 'day') {
      return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
    }
    return d.toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short', hour12: false });
  }

  function buildTimeline(data, bucket) {
    destroy('timeline');
    const ctx = document.getElementById('chart-timeline');
    charts.timeline = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.map((d) => fmtBucket(d.bucket, bucket)),
        datasets: [
          {
            label: 'Sessions',
            data: data.map((d) => d.count),
            borderColor: palette.line,
            backgroundColor: palette.fill,
            tension: 0.25,
            fill: true,
            yAxisID: 'y',
          },
          {
            label: 'Avg threat score',
            data: data.map((d) => d.avg_score),
            borderColor: palette.medium,
            backgroundColor: 'rgba(210,153,34,0.1)',
            tension: 0.25,
            yAxisID: 'y1',
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
          y: { beginAtZero: true, title: { display: true, text: 'Sessions' } },
          y1: {
            beginAtZero: true,
            position: 'right',
            grid: { drawOnChartArea: false },
            title: { display: true, text: 'Avg score' },
            max: 100,
          },
        },
      },
    });
  }

  function buildSeverity(breakdown) {
    destroy('severity');
    const labels = ['low', 'medium', 'high', 'critical'];
    const ctx = document.getElementById('chart-severity');
    charts.severity = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: labels.map((l) => breakdown[l] || 0),
          backgroundColor: labels.map((l) => palette[l]),
          borderColor: 'rgba(14,17,22,0.6)',
        }],
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } },
    });
  }

  function buildServices(svc) {
    destroy('services');
    const labels = Object.keys(svc);
    const ctx = document.getElementById('chart-services');
    charts.services = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Sessions',
          data: labels.map((k) => svc[k]),
          backgroundColor: labels.map((k) => palette.services[k] || palette.bar),
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } },
      },
    });
  }

  function buildTTPs(rows) {
    destroy('ttps');
    const ctx = document.getElementById('chart-ttps');
    charts.ttps = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: rows.map((r) => `${r.technique_id} — ${r.name}`),
        datasets: [{
          label: 'Sessions',
          data: rows.map((r) => r.count),
          backgroundColor: palette.bar,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true } },
      },
    });
  }

  function buildGeo(rows) {
    destroy('geo');
    const ctx = document.getElementById('chart-geo');
    charts.geo = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: rows.map((r) => r.country_iso || '??'),
        datasets: [{
          label: 'Sessions',
          data: rows.map((r) => r.count),
          backgroundColor: palette.bar,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } },
      },
    });
  }

  async function refresh() {
    const form = document.getElementById('window-form');
    const days = Number(new FormData(form).get('days')) || 7;
    const bucket = new FormData(form).get('bucket') || 'hour';

    try {
      const [overviewR, timelineR, ttpsR, geoR] = await Promise.all([
        window.HS.apiFetch(`/api/stats/overview?days=${days}`),
        window.HS.apiFetch(`/api/stats/timeline?days=${days}&bucket=${bucket}`),
        window.HS.apiFetch(`/api/stats/ttps?days=${days}&limit=10`),
        window.HS.apiFetch(`/api/stats/geo?days=${days}&limit=15`),
      ]);
      if (!overviewR.ok || !timelineR.ok || !ttpsR.ok || !geoR.ok) {
        throw new Error('one or more stats endpoints failed');
      }
      const overview = await overviewR.json();
      const timeline = await timelineR.json();
      const ttps = await ttpsR.json();
      const geo = await geoR.json();

      const oWrap = document.getElementById('overview');
      oWrap.querySelector('[data-key="total_sessions"]').textContent = overview.total_sessions;
      oWrap.querySelector('[data-key="unique_ips"]').textContent = overview.unique_ips;
      oWrap.querySelector('[data-key="avg_threat_score"]').textContent = overview.avg_threat_score.toFixed(1);
      oWrap.querySelector('[data-key="severity_critical"]').textContent = (overview.severity_breakdown || {}).critical || 0;

      buildTimeline(timeline, bucket);
      buildSeverity(overview.severity_breakdown || {});
      buildServices(overview.sessions_by_service || {});
      buildTTPs(ttps);
      buildGeo(geo);
    } catch (e) {
      console.warn('analytics refresh failed', e);
    }
  }

  function init() {
    if (typeof Chart === 'undefined') {
      // Chart.js may still be loading (defer). Try again on next tick.
      setTimeout(init, 100);
      return;
    }
    if (!window.HS || !window.HS.getToken()) return;
    document.getElementById('window-form').addEventListener('submit', (e) => {
      e.preventDefault();
      refresh();
    });
    refresh();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
