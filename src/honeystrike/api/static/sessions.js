// Sessions browser. Filters → /api/sessions, paginated table, deep-link state
// stored in the URL hash so a refresh keeps the same view.

(function () {
  const tbody = document.getElementById('sessions-full-tbody');
  const summary = document.getElementById('meta-summary');
  const pager = document.getElementById('pager');
  const form = document.getElementById('filters');

  function severityClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString('en-GB', { hour12: false });
  }

  function fmtDuration(ms) {
    if (ms == null) return '—';
    if (ms < 1000) return `${ms} ms`;
    if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
    return `${(ms / 60_000).toFixed(1)} min`;
  }

  function readForm() {
    const fd = new FormData(form);
    const out = {};
    for (const [k, v] of fd.entries()) {
      if (v !== '' && v != null) out[k] = v;
    }
    return out;
  }

  function writeForm(state) {
    for (const el of form.elements) {
      if (!el.name) continue;
      if (state[el.name] != null) el.value = state[el.name];
    }
  }

  function readHash() {
    if (!window.location.hash) return { page: 1 };
    try {
      return JSON.parse(decodeURIComponent(window.location.hash.slice(1)));
    } catch {
      return { page: 1 };
    }
  }

  function writeHash(state) {
    window.location.hash = encodeURIComponent(JSON.stringify(state));
  }

  function toQuery(state) {
    const params = new URLSearchParams();
    params.set('page', state.page || 1);
    params.set('limit', state.limit || 50);
    if (state.service) params.set('service', state.service);
    if (state.min_score) params.set('min_score', state.min_score);
    if (state.from_ts) params.set('from_ts', new Date(state.from_ts).toISOString());
    if (state.to_ts) params.set('to_ts', new Date(state.to_ts).toISOString());
    return params.toString();
  }

  function renderPager(state, total) {
    const limit = Number(state.limit || 50);
    const page = Number(state.page || 1);
    const pages = Math.max(1, Math.ceil(total / limit));
    pager.innerHTML = '';
    const mk = (label, target, disabled) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = label;
      b.disabled = disabled;
      if (!disabled) {
        b.addEventListener('click', () => {
          state.page = target;
          writeHash(state);
          load(state);
        });
      }
      pager.appendChild(b);
    };
    mk('« First', 1, page <= 1);
    mk('‹ Prev', page - 1, page <= 1);
    const span = document.createElement('span');
    span.textContent = ` Page ${page} of ${pages} `;
    span.className = 'pager-label';
    pager.appendChild(span);
    mk('Next ›', page + 1, page >= pages);
    mk('Last »', pages, page >= pages);
  }

  async function load(state) {
    summary.textContent = 'Loading…';
    tbody.innerHTML = '';
    try {
      const r = await window.HS.apiFetch('/api/sessions?' + toQuery(state));
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      summary.textContent = `${data.total.toLocaleString()} session(s) match — showing ${data.items.length}`;
      if (!data.items.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="muted">No sessions match these filters.</td></tr>';
      } else {
        for (const s of data.items) {
          const tr = document.createElement('tr');
          tr.addEventListener('click', () => {
            window.location.href = `/sessions/${s.id}`;
          });
          tr.innerHTML = `
            <td>${fmtTime(s.started_at)}</td>
            <td>${s.service}</td>
            <td><code>${s.src_ip}</code></td>
            <td>${s.country_iso || '—'}</td>
            <td>${s.state}</td>
            <td>${fmtDuration(s.duration_ms)}</td>
            <td>${s.ttp_count}</td>
            <td><span class="score-pill score-${severityClass(s.threat_score)}">${s.threat_score}</span></td>
          `;
          tbody.appendChild(tr);
        }
      }
      renderPager(state, data.total);
    } catch (e) {
      summary.textContent = 'Failed to load: ' + e.message;
      tbody.innerHTML = '';
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const state = { ...readForm(), page: 1 };
    writeHash(state);
    load(state);
  });
  document.getElementById('filters-reset').addEventListener('click', (e) => {
    e.preventDefault();
    form.reset();
    const state = { page: 1, limit: 50 };
    writeHash(state);
    load(state);
  });

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    const state = readHash();
    writeForm(state);
    load(state);
  });
})();
