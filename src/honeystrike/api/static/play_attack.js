// /play/attack — scenario picker + live attack launcher.

(function () {
  const grid = document.getElementById('scenario-grid');
  const launcher = document.getElementById('launcher');
  const pickedLabel = document.getElementById('picked-label');
  const form = document.getElementById('launch-form');
  const tbody = document.getElementById('tasks-tbody');
  const cancelBtn = document.getElementById('cancel-pick');

  let picked = null;
  const tasks = new Map();          // task_id -> tr element

  function severityClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  async function loadScenarios() {
    const r = await window.HS.apiFetch('/api/play/scenarios');
    if (!r.ok) {
      grid.innerHTML = `<p class="error">Failed to load (HTTP ${r.status}).</p>`;
      return;
    }
    const data = await r.json();
    grid.innerHTML = '';
    for (const s of data.scenarios) {
      const card = document.createElement('div');
      card.className = 'scenario-card';
      card.dataset.type = 'scenario';
      card.dataset.id = s.id;
      card.dataset.default = s.default_target;
      card.innerHTML = `
        <div class="badge ${s.service}">${s.service}</div>
        <h3>${s.label}</h3>
        <p>${s.blurb}</p>
        <p class="ttp-row">${(s.expected_ttps || []).map(t => `<span class="ttp">${t}</span>`).join('') || '<span class="muted">no TTPs</span>'}</p>
      `;
      card.addEventListener('click', () => pick(s, false));
      grid.appendChild(card);
    }
    for (const c of data.campaigns) {
      const card = document.createElement('div');
      card.className = 'scenario-card campaign';
      card.dataset.type = 'campaign';
      card.dataset.id = c.id;
      card.innerHTML = `
        <div class="badge campaign-badge">campaign</div>
        <h3>${c.label}</h3>
        <p>${c.blurb}</p>
        <p class="ttp-row">${(c.expected_ttps || []).map(t => `<span class="ttp">${t}</span>`).join('') || ''}</p>
      `;
      card.addEventListener('click', () => pick(c, true));
      grid.appendChild(card);
    }
    refreshTasks();
  }

  function pick(scenarioOrCampaign, isCampaign) {
    picked = { ...scenarioOrCampaign, isCampaign };
    pickedLabel.textContent = picked.label || picked.id;
    form.elements['target'].value = picked.default_target || 'ssh-honeypot';
    form.elements['count'].value = '';
    form.elements['keep_shell'].checked = picked.id === 'ssh-hydra';
    launcher.hidden = false;
    launcher.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  cancelBtn.addEventListener('click', () => {
    launcher.hidden = true;
    picked = null;
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!picked) return;
    const fd = new FormData(form);
    const body = picked.isCampaign
      ? { name: picked.id, target_host: (fd.get('target') || '').split(':')[0] }
      : {
          scenario: picked.id,
          target: fd.get('target') || null,
          intensity: fd.get('intensity'),
          count: fd.get('count') ? Number(fd.get('count')) : null,
          keep_shell: !!fd.get('keep_shell'),
        };
    const path = picked.isCampaign ? '/api/play/campaign' : '/api/play/attack';
    const r = await window.HS.apiFetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      alert(`launch failed: HTTP ${r.status}`);
      return;
    }
    const task = await r.json();
    addTask(task);
    launcher.hidden = true;
    picked = null;
    pollTask(task.task_id);
  });

  function addTask(task) {
    if (tbody.firstElementChild && tbody.firstElementChild.matches('tr.empty')) {
      tbody.innerHTML = '';
    } else if (tbody.children.length === 1
               && tbody.firstElementChild.querySelector('.muted')) {
      tbody.innerHTML = '';
    }
    const tr = document.createElement('tr');
    tr.dataset.taskId = task.task_id;
    renderTask(tr, task);
    tbody.insertBefore(tr, tbody.firstChild);
    tasks.set(task.task_id, tr);
  }

  function renderTask(tr, task) {
    const startedTxt = new Date(task.started_at * 1000).toLocaleTimeString('en-GB', { hour12: false });
    let result = '—';
    if (task.status === 'done' && task.summary) {
      result = Object.entries(task.summary)
        .filter(([k]) => !k.startsWith('_'))
        .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
        .join(' · ');
    } else if (task.status === 'failed') {
      result = task.error || 'failed';
    }
    tr.innerHTML = `
      <td>${startedTxt}</td>
      <td>${task.scenario}</td>
      <td><code>${task.target}</code></td>
      <td>${task.phase}</td>
      <td class="status-${task.status}">${task.status}</td>
      <td>${result}</td>
    `;
  }

  async function pollTask(taskId) {
    while (true) {
      await new Promise(r => setTimeout(r, 1000));
      const r = await window.HS.apiFetch(`/api/play/attack/${taskId}`);
      if (!r.ok) break;
      const task = await r.json();
      const tr = tasks.get(taskId);
      if (tr) renderTask(tr, task);
      if (task.status !== 'running') break;
    }
  }

  async function refreshTasks() {
    const r = await window.HS.apiFetch('/api/play/tasks');
    if (!r.ok) return;
    const list = await r.json();
    tbody.innerHTML = '';
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No runs yet.</td></tr>';
      return;
    }
    for (const t of list) addTask(t);
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    loadScenarios();
  });
})();
