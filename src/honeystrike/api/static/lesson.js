// /play/<family>/<id> — typing-driven lesson engine.
//
// Loads /api/lessons/<family>/<id>, walks the blocks array, runs the
// typing game on `code` / `shell` blocks, the multiple-choice on `choice`,
// and renders `prose` between them. The mascot reacts to every keystroke.

(function () {
  const root = document.querySelector('.lesson-page');
  const family = root.dataset.lessonFamily;
  const lessonId = root.dataset.lessonId;

  const codeEl = document.getElementById('lesson-code');
  const noteEl = document.getElementById('lesson-annotation');
  const titleEl = document.getElementById('lesson-title');
  const briefEl = document.getElementById('lesson-briefing');
  const progressEl = document.getElementById('lesson-progress');
  const replayBtn = document.getElementById('replay-fixture-btn');
  const fireBtn = document.getElementById('fire-live-btn');
  const gradeBtn = document.getElementById('grade-btn');
  const outSection = document.getElementById('lesson-output');
  const outPre = document.getElementById('lesson-output-pre');

  let lesson = null;
  let blockIdx = 0;
  let cursor = 0;          // chars typed in current block

  // ---- mascot helpers --------------------------------------------------
  const mascot = document.getElementById('mascot');
  const bubbleText = document.getElementById('mascot-bubble-text');

  let mascotResetTimer = null;
  function setMascot(state, text) {
    if (!mascot) return;
    mascot.classList.remove('idle', 'happy', 'shock', 'cheer', 'sleep');
    mascot.classList.add(state);
    if (text != null && bubbleText) bubbleText.textContent = text;
    if (state === 'shock' || state === 'happy' || state === 'cheer') {
      clearTimeout(mascotResetTimer);
      mascotResetTimer = setTimeout(() => {
        mascot.classList.remove(state);
        mascot.classList.add('idle');
      }, state === 'cheer' ? 1400 : 380);
    }
  }

  let idleTimer = null;
  function bumpIdle() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => setMascot('sleep', '…zzz… (tap anywhere to wake me)'), 30_000);
  }

  // ---- markdown-ish renderer (only what briefings use) -----------------
  function renderBriefing(md) {
    // tiny renderer: paragraphs, **bold**, *italic*, `code`, [text](url),
    // and tables. Not a CommonMark parser; just enough for our lessons.
    const lines = md.split(/\r?\n/);
    let html = '';
    let inTable = false;
    let buf = [];
    function flushPara() {
      if (!buf.length) return;
      let p = buf.join(' ').trim();
      if (p) html += `<p>${inlineFmt(p)}</p>`;
      buf = [];
    }
    function inlineFmt(s) {
      return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\*([^*]+)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
    }
    for (const raw of lines) {
      const line = raw.trimEnd();
      if (/^\s*\|.*\|\s*$/.test(line)) {
        if (!inTable) { flushPara(); html += '<table class="brief-tbl">'; inTable = true; }
        const cells = line.trim().slice(1, -1).split('|').map(c => c.trim());
        if (cells.every(c => /^-+$/.test(c))) continue;        // separator row
        html += '<tr>' + cells.map(c => `<td>${inlineFmt(c)}</td>`).join('') + '</tr>';
        continue;
      } else if (inTable) {
        html += '</table>'; inTable = false;
      }
      if (line === '') { flushPara(); continue; }
      buf.push(line);
    }
    flushPara();
    if (inTable) html += '</table>';
    return html;
  }

  // ---- block rendering --------------------------------------------------
  function renderAllBlocks() {
    codeEl.innerHTML = '';
    lesson.blocks.forEach((b, i) => {
      const wrap = document.createElement('div');
      wrap.className = `block block-${b.kind}`;
      wrap.dataset.idx = i;
      if (b.kind === 'prose') {
        wrap.innerHTML = `<p class="prose">${escapeHtml(b.text)}</p>`;
      } else if (b.kind === 'choice') {
        wrap.innerHTML = `
          <p class="choice-prompt">${escapeHtml(b.prompt)}</p>
          <ul class="choice-options">
            ${b.options.map((o, j) => `<li><button type="button" data-choice="${j}">${escapeHtml(o)}</button></li>`).join('')}
          </ul>
          <p class="choice-feedback muted"></p>`;
        wrap.querySelectorAll('button[data-choice]').forEach(btn => {
          btn.addEventListener('click', () => handleChoice(i, Number(btn.dataset.choice)));
        });
      } else {
        // code or shell
        const isShell = b.kind === 'shell';
        wrap.innerHTML = `
          ${isShell ? '<span class="prompt">$</span> ' : ''}<span class="typed"></span><span class="caret">▌</span><span class="ghost"></span>`;
      }
      codeEl.appendChild(wrap);
    });
    paintTypingBlock();
    updateAnnotation();
    updateProgress();
  }

  function paintTypingBlock() {
    // Dim past + future, highlight current typing block.
    document.querySelectorAll('.block').forEach((el, i) => {
      el.classList.remove('active', 'done', 'pending');
      if (i < blockIdx) el.classList.add('done');
      else if (i === blockIdx) el.classList.add('active');
      else el.classList.add('pending');
    });
    const cur = currentBlockEl();
    if (!cur || !isTypingKind(currentBlock())) return;
    const target = currentBlock().target;
    const typed = target.slice(0, cursor);
    const ghost = target.slice(cursor);
    cur.querySelector('.typed').textContent = typed;
    cur.querySelector('.ghost').textContent = ghost;
  }

  function escapeHtml(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function isTypingKind(b) { return b && (b.kind === 'code' || b.kind === 'shell'); }
  function currentBlock() { return lesson.blocks[blockIdx]; }
  function currentBlockEl() { return codeEl.querySelector(`.block[data-idx="${blockIdx}"]`); }

  function updateAnnotation() {
    const b = currentBlock();
    if (!b) {
      noteEl.innerHTML = '<p>🎉 Lesson complete. Replay the fixture or fire live!</p>';
      return;
    }
    if (b.kind === 'prose') {
      noteEl.innerHTML = `<p class="muted">${escapeHtml(b.text)}</p>`;
    } else if (b.kind === 'choice') {
      noteEl.innerHTML = `<p class="muted">Pick the best answer. We'll tell you why it's right or wrong.</p>`;
    } else {
      noteEl.innerHTML = `<p>${escapeHtml(b.annotation || '')}</p>`;
    }
  }

  let lessonRewarded = false;
  function updateProgress() {
    progressEl.textContent = `${Math.min(blockIdx, lesson.blocks.length)} / ${lesson.blocks.length} blocks`;
    if (blockIdx >= lesson.blocks.length) {
      replayBtn.disabled = !lesson.fixture;
      fireBtn.disabled = !lesson.live;
      if (family === 'defend') {
        gradeBtn.hidden = false;
        gradeBtn.disabled = false;
      }
      setMascot('cheer', '🎉 You typed the whole thing. Try replay or fire live!');
      if (!lessonRewarded && window.HSGame) {
        lessonRewarded = true;
        window.HSGame.onLessonComplete(family, lessonId);
      }
    }
  }

  // ---- non-typing block handling ---------------------------------------
  function advanceProse() {
    blockIdx += 1;
    afterAdvance();
  }

  function handleChoice(idx, pick) {
    if (idx !== blockIdx) return;
    const b = currentBlock();
    const fb = currentBlockEl().querySelector('.choice-feedback');
    if (pick === b.correct) {
      fb.textContent = '✓ ' + (b.explanation || 'Correct.');
      fb.className = 'choice-feedback ok';
      setMascot('happy', 'Nice — that\'s the right read.');
      setTimeout(() => { blockIdx += 1; afterAdvance(); }, 350);
    } else {
      fb.textContent = '✗ ' + (b.explanation || 'Try again.');
      fb.className = 'choice-feedback bad';
      setMascot('shock', 'Not quite. Re-read the prompt and try once more.');
    }
  }

  function afterAdvance() {
    cursor = 0;
    paintTypingBlock();
    updateAnnotation();
    updateProgress();
    // Auto-advance through consecutive prose blocks so users don't get stuck.
    while (currentBlock() && currentBlock().kind === 'prose') {
      // Show prose for a beat, then advance on space/enter — but auto-advance
      // immediately if the next item is also prose? No: show one prose at a
      // time, advance on any key. Simplest: leave it; the key handler below
      // catches it.
      break;
    }
  }

  // ---- typing handler --------------------------------------------------
  function onKey(ev) {
    bumpIdle();
    if (blockIdx >= lesson.blocks.length) return;
    const b = currentBlock();
    if (b.kind === 'prose') {
      // Any printable key, Enter, or space advances.
      if (ev.key === 'Enter' || ev.key === ' ' || ev.key.length === 1) {
        ev.preventDefault();
        advanceProse();
      }
      return;
    }
    if (b.kind === 'choice') return;     // handled by button clicks

    // Typing block.
    if (ev.key === 'Tab') {
      ev.preventDefault();
      cursor = b.target.length;
      paintTypingBlock();
      onBlockComplete();
      return;
    }
    if (ev.key === 'Escape') {
      ev.preventDefault();
      cursor = b.target.length;
      paintTypingBlock();
      setMascot('shock', 'Spoiler granted. Try the next block from scratch!');
      onBlockComplete();
      return;
    }
    if (ev.key === 'Backspace') {
      ev.preventDefault();
      if (cursor > 0) {
        cursor -= 1;
        paintTypingBlock();
      }
      return;
    }
    // Single-character keys only from here on.
    if (ev.key.length !== 1 && ev.key !== 'Enter') return;
    ev.preventDefault();

    const expect = b.target[cursor];
    const got = ev.key === 'Enter' ? '\n' : ev.key;
    const ok = (got === expect) || (b.kind === 'shell' && expect && got.toLowerCase() === expect.toLowerCase());
    if (ok) {
      cursor += 1;
      paintTypingBlock();
      setMascot('happy');
      if (cursor >= b.target.length) onBlockComplete();
    } else {
      setMascot('shock', `Expected '${expect}', got '${got}'.`);
      flashWrong();
    }
  }

  function flashWrong() {
    const el = currentBlockEl();
    if (!el) return;
    el.classList.add('flash-wrong');
    setTimeout(() => el.classList.remove('flash-wrong'), 280);
  }

  function onBlockComplete() {
    blockIdx += 1;
    setMascot('cheer', 'Block locked in.');
    afterAdvance();
  }

  // ---- replay fixture / fire live --------------------------------------
  async function replayFixture() {
    if (!lesson.fixture || !lesson.fixture.events_json) return;
    outSection.hidden = false;
    outPre.textContent = 'Loading fixture…\n';
    try {
      const r = await window.HS.apiFetch(`/api/lessons/fixtures/${encodeURIComponent(lesson.fixture.events_json)}`);
      if (!r.ok) { outPre.textContent += `Failed to load fixture (HTTP ${r.status})`; return; }
      const fx = await r.json();
      outPre.textContent = `Fixture: ${fx.service} session from ${fx.src_ip}\n`;
      outPre.textContent += '---\n';
      for (const ev of fx.events || []) {
        await sleep(220);
        outPre.textContent += `[${(ev.ts || '').slice(11, 19)}] ${ev.event_type} ${JSON.stringify(ev.payload).slice(0, 140)}\n`;
        outPre.scrollTop = outPre.scrollHeight;
      }
      outPre.textContent += '---\n';
      if (family === 'defend') {
        outPre.textContent += 'Now click "Grade my detector" to see if the reference rule fires.\n';
      }
    } catch (e) {
      outPre.textContent += `error: ${e.message || e}\n`;
    }
  }

  async function fireLive() {
    if (!lesson.live || !lesson.live.scenario) return;
    outSection.hidden = false;
    outPre.textContent = `Firing ${lesson.live.scenario} at ${lesson.live.default_target}…\n`;
    try {
      const r = await window.HS.apiFetch('/api/play/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: lesson.live.scenario,
          target: lesson.live.default_target,
          intensity: 'burst',
        }),
      });
      if (!r.ok) { outPre.textContent += `launch failed: HTTP ${r.status}\n`; return; }
      const task = await r.json();
      outPre.textContent += `task ${task.task_id} → ${task.status}\n`;
      while (true) {
        await sleep(800);
        const rr = await window.HS.apiFetch(`/api/play/attack/${task.task_id}`);
        if (!rr.ok) break;
        const cur = await rr.json();
        outPre.textContent += `phase=${cur.phase} status=${cur.status}\n`;
        outPre.scrollTop = outPre.scrollHeight;
        if (cur.status !== 'running') {
          outPre.textContent += `\nSummary: ${JSON.stringify(cur.summary || cur.error)}\n`;
          break;
        }
      }
    } catch (e) {
      outPre.textContent += `error: ${e.message || e}\n`;
    }
  }

  async function gradeDefender() {
    outSection.hidden = false;
    outPre.textContent = 'Running reference rule against fixture…\n';
    try {
      const r = await window.HS.apiFetch('/api/lessons/grade-defender', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lesson_id: lessonId }),
      });
      if (!r.ok) { outPre.textContent += `grade failed: HTTP ${r.status}\n`; return; }
      const out = await r.json();
      outPre.textContent += `fired=${out.fired}  expected=${out.expected}  correct=${out.correct}\n`;
      if (out.technique_id) {
        outPre.textContent += `→ ${out.technique_id} (${out.technique_name}) @ confidence ${out.confidence}\n`;
      }
      outPre.textContent += `\n${out.narrative}\n`;
      setMascot(out.correct ? 'cheer' : 'shock', out.correct ? 'Detection looks right!' : 'Reference rule disagrees — re-read the body.');
      if (window.HSGame) {
        if (out.correct) window.HSGame.onCorrectLabel();
        else             window.HSGame.onWrongLabel();
      }
      if (out.reference_source_excerpt) {
        outPre.textContent += `\n--- reference body ---\n${out.reference_source_excerpt}\n`;
      }
    } catch (e) {
      outPre.textContent += `error: ${e.message || e}\n`;
    }
  }

  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  // ---- boot ------------------------------------------------------------
  async function load() {
    const r = await window.HS.apiFetch(`/api/lessons/${family}/${lessonId}`);
    if (!r.ok) {
      titleEl.textContent = 'Lesson not found';
      briefEl.innerHTML = `<p class="error">HTTP ${r.status}</p>`;
      return;
    }
    lesson = await r.json();
    titleEl.textContent = lesson.title;
    briefEl.innerHTML = renderBriefing(lesson.briefing || '');
    renderAllBlocks();
    bumpIdle();
    setMascot('idle', 'Type the highlighted line. Tab = autocomplete, Esc = reveal.');
  }

  replayBtn.addEventListener('click', replayFixture);
  fireBtn.addEventListener('click', fireLive);
  gradeBtn.addEventListener('click', gradeDefender);
  document.addEventListener('keydown', onKey);

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    load();
  });
})();
