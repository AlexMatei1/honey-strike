// /admin/users — SOC Lead account management.
// The API enforces admin-only; this page also gates the UI on /api/auth/me.

(function () {
  const denied = document.getElementById('users-denied');
  const wrap = document.getElementById('users-wrap');
  const tbody = document.getElementById('users-tbody');

  function fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 86_400) return `${Math.max(1, Math.floor(diff / 3600))}h ago`;
    if (diff < 30 * 86_400) return `${Math.floor(diff / 86_400)}d ago`;
    return d.toLocaleDateString();
  }
  function esc(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  async function load() {
    const r = await window.HS.apiFetch('/api/admin/users');
    if (r.status === 403) { denied.hidden = false; return; }
    if (!r.ok) { tbody.innerHTML = `<tr><td colspan="8" class="error">HTTP ${r.status}</td></tr>`; wrap.hidden = false; return; }
    wrap.hidden = false;
    const users = await r.json();
    render(users);
  }

  function render(users) {
    tbody.innerHTML = '';
    for (const u of users) {
      const tr = document.createElement('tr');
      if (!u.is_active) tr.className = 'inactive';
      const toRole = u.role === 'admin' ? 'member' : 'admin';
      const roleBtn = u.role === 'admin' ? 'Demote to Analyst' : 'Promote to Lead';
      const actBtn = u.is_active ? 'Deactivate' : 'Reactivate';
      tr.innerHTML = `
        <td><strong>${esc(u.username)}</strong></td>
        <td><span class="role-pill ${u.role}">${u.role === 'admin' ? '🛡 Lead' : '🔍 Analyst'}</span></td>
        <td>${esc(u.rank)}</td>
        <td>${u.xp}</td>
        <td>${u.is_active ? '🟢 active' : '⚪ inactive'}</td>
        <td>${fmtDate(u.created_at)}</td>
        <td>${fmtDate(u.last_login_at)}</td>
        <td>
          <button type="button" data-act="role" data-id="${u.id}" data-to="${toRole}">${roleBtn}</button>
          <button type="button" data-act="active" data-id="${u.id}" data-to="${u.is_active ? 'false' : 'true'}">${actBtn}</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', () => action(btn));
    });
  }

  async function action(btn) {
    const id = btn.dataset.id;
    btn.disabled = true;
    try {
      let r;
      if (btn.dataset.act === 'role') {
        r = await window.HS.apiFetch(`/api/admin/users/${id}/role`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: btn.dataset.to }),
        });
      } else {
        r = await window.HS.apiFetch(`/api/admin/users/${id}/active`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ is_active: btn.dataset.to === 'true' }),
        });
      }
      if (!r.ok) {
        let msg = `HTTP ${r.status}`;
        try { const j = await r.json(); if (j.detail) msg = j.detail; } catch {}
        if (window.HSGame) window.HSGame.woops(msg);
        btn.disabled = false;
        return;
      }
      await load();        // refresh the table
    } catch (e) {
      if (window.HSGame) window.HSGame.woops(e.message || 'error');
      btn.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    load();
  });
})();
