// /play/defend — lesson hub. Renders one card per defender lesson.

(function () {
  const list = document.getElementById('hub-list');

  async function load() {
    const r = await window.HS.apiFetch('/api/lessons');
    if (!r.ok) { list.innerHTML = `<p class="error">HTTP ${r.status}</p>`; return; }
    const cat = await r.json();
    const items = cat.defend || [];
    if (!items.length) { list.innerHTML = '<p class="muted">No lessons yet.</p>'; return; }
    list.innerHTML = '';
    for (const l of items) {
      const card = document.createElement('a');
      card.className = `lesson-card diff-${l.difficulty}`;
      card.href = `/play/defend/${l.id}`;
      card.innerHTML = `
        <div class="lesson-card-head">
          <span class="diff-badge">${l.difficulty}</span>
          <span class="model-badge">${l.typing_model}</span>
        </div>
        <h3>${l.title}</h3>
        <p>${l.blurb || ''}</p>
        <p class="ttp-row">${(l.ttps || []).map(t => `<span class="ttp">${t}</span>`).join('')}</p>
      `;
      list.appendChild(card);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    load();
  });
})();
