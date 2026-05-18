// /sessions/{id}/replay — animated session playback.
//
// Pulls the full event timeline + synthesised score timeline from
// /api/replay/{id} and replays it: events appear in the log at their
// recorded offsets, the threat-score bar climbs through the synthesised
// frames. Speed control, play/pause, reset, scrubber.

(function () {
  const sessionIdEl = document.getElementById('session-id');
  const playBtn = document.getElementById('play-btn');
  const pauseBtn = document.getElementById('pause-btn');
  const resetBtn = document.getElementById('reset-btn');
  const speedSel = document.getElementById('speed');
  const elapsedEl = document.getElementById('elapsed');
  const durationEl = document.getElementById('duration');
  const scrubber = document.getElementById('scrubber');
  const scoreFill = document.getElementById('score-fill');
  const scoreValue = document.getElementById('score-value');
  const scoreSev = document.getElementById('score-severity');
  const scoreLast = document.getElementById('score-last');
  const eventLog = document.getElementById('event-log');

  const sessionId = (sessionIdEl?.textContent || '').trim();
  let data = null;                 // ReplayOut
  let totalMs = 0;
  let playing = false;
  let baseWall = 0;                // performance.now() at last play start
  let baseOffset = 0;              // virtual ms already consumed before this play
  let rafHandle = null;

  function severityClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  function fmtMs(ms) {
    if (!isFinite(ms) || ms < 0) ms = 0;
    const totalSec = ms / 1000;
    const m = Math.floor(totalSec / 60);
    const s = totalSec - m * 60;
    return `${String(m).padStart(2, '0')}:${s.toFixed(3).padStart(6, '0')}`;
  }

  async function load() {
    eventLog.innerHTML = '<p class="muted">Loading…</p>';
    const r = await window.HS.apiFetch(`/api/replay/${sessionId}`);
    if (!r.ok) {
      eventLog.innerHTML = `<p class="error">Failed to load (HTTP ${r.status}).</p>`;
      return;
    }
    data = await r.json();
    // Use the larger of: last event offset, score-frame offset, session duration_ms.
    const lastEvt = data.events.length ? data.events[data.events.length - 1].t_ms : 0;
    const lastFrame = data.score_timeline.length
      ? data.score_timeline[data.score_timeline.length - 1].t_ms : 0;
    totalMs = Math.max(lastEvt, lastFrame, data.duration_ms || 0, 1000);
    durationEl.textContent = fmtMs(totalMs);
    renderHeader();
    reset();
  }

  function renderHeader() {
    const ttps = (data.ttps || []).map(t =>
      `<span class="ttp">${t.technique_id}</span>`).join(' ');
    const tools = (data.tool_signatures || []).map(t =>
      `<span class="tool">${t.tool || t.name || 'tool'}</span>`).join(' ');
    eventLog.innerHTML = `
      <div class="replay-meta">
        <p><strong>${data.service.toUpperCase()}</strong>
           from <code>${data.src_ip}</code> ·
           final score <strong>${data.final_score}</strong>
           (<span class="sev-${severityClass(data.final_score)}">${data.final_severity}</span>)</p>
        <p>TTPs: ${ttps || '<span class="muted">none</span>'}</p>
        ${tools ? `<p>Tools: ${tools}</p>` : ''}
        <hr>
      </div>
      <p class="muted">Press ▶ Play to begin the timeline.</p>
    `;
  }

  function reset() {
    pause();
    baseOffset = 0;
    scrubber.value = 0;
    elapsedEl.textContent = fmtMs(0);
    updateScoreBar(0);
    renderHeader();
  }

  function play() {
    if (!data || playing) return;
    if (baseOffset >= totalMs) baseOffset = 0;       // restart from top after a finished play
    playing = true;
    baseWall = performance.now();
    playBtn.disabled = true;
    pauseBtn.disabled = false;
    tick();
  }

  function pause() {
    if (!playing) {
      playBtn.disabled = !data;
      pauseBtn.disabled = true;
      return;
    }
    playing = false;
    const delta = (performance.now() - baseWall) * speed();
    baseOffset = Math.min(totalMs, baseOffset + delta);
    if (rafHandle) cancelAnimationFrame(rafHandle);
    playBtn.disabled = !data;
    pauseBtn.disabled = true;
  }

  function speed() {
    return Number(speedSel.value) || 1;
  }

  function currentVirtualMs() {
    if (!playing) return baseOffset;
    const delta = (performance.now() - baseWall) * speed();
    return Math.min(totalMs, baseOffset + delta);
  }

  function tick() {
    if (!playing) return;
    const now = currentVirtualMs();
    elapsedEl.textContent = fmtMs(now);
    scrubber.value = String((now / totalMs) * 100);
    syncTimelineTo(now);
    if (now >= totalMs) {
      pause();
      return;
    }
    rafHandle = requestAnimationFrame(tick);
  }

  let lastEventIndex = -1;
  let lastFrameIndex = -1;

  function syncTimelineTo(virtualMs) {
    if (!data) return;
    // Catch up event log.
    while (lastEventIndex + 1 < data.events.length &&
           data.events[lastEventIndex + 1].t_ms <= virtualMs) {
      lastEventIndex += 1;
      appendEvent(data.events[lastEventIndex]);
    }
    // Catch up score frames.
    let lastFrame = null;
    while (lastFrameIndex + 1 < data.score_timeline.length &&
           data.score_timeline[lastFrameIndex + 1].t_ms <= virtualMs) {
      lastFrameIndex += 1;
      lastFrame = data.score_timeline[lastFrameIndex];
    }
    if (lastFrame) {
      updateScoreBar(lastFrame.running_score);
      scoreLast.textContent = `+${lastFrame.delta} from ${lastFrame.label}`;
    }
  }

  function appendEvent(ev) {
    if (eventLog.querySelector('p.muted')) {
      // Strip the "Press ▶ Play" hint after first event lands.
      const hint = eventLog.querySelector('p.muted');
      if (hint) hint.remove();
    }
    const div = document.createElement('div');
    div.className = `event-row event-${ev.event_type.toLowerCase()}`;
    const snippet = summarisePayload(ev);
    div.innerHTML = `
      <span class="event-ts">${fmtMs(ev.t_ms)}</span>
      <span class="event-type">${ev.event_type}</span>
      <span class="event-snippet">${snippet}</span>
    `;
    eventLog.appendChild(div);
    eventLog.scrollTop = eventLog.scrollHeight;
  }

  function summarisePayload(ev) {
    const p = ev.payload || {};
    switch (ev.event_type) {
      case 'SSH_AUTH_ATTEMPT':
        return `${p.username || '?'}:${p.password ? '••••' : ''} → ${p.granted ? 'GRANTED' : 'denied'}`;
      case 'SSH_COMMAND':
        return `<code>${(p.command || '').slice(0, 80)}</code>`;
      case 'HTTP_REQUEST':
        return `${p.method || 'GET'} ${p.path || p.uri || '/'}` +
               (p.cve_signature ? ` <em>(${p.cve_signature})</em>` : '') +
               (p.sqli_pattern ? ' <em>(SQLi)</em>' : '') +
               (p.path_traversal ? ' <em>(traversal)</em>' : '') +
               (p.scanner_detected ? ` <em>(${p.scanner_detected})</em>` : '');
      case 'FTP_COMMAND':
        return `${p.command || ''} ${(p.args || '').slice(0, 40)}`;
      case 'RDP_CONNECT':
        return `cookie=${p.cookie || '?'}`;
      case 'TLS_CLIENT_HELLO':
        return `sni=${p.sni || ''} ja3=${(p.ja3_hash || '').slice(0, 12)}`;
      default:
        return '';
    }
  }

  function updateScoreBar(score) {
    const pct = Math.max(0, Math.min(100, Math.round(score)));
    scoreFill.style.width = `${pct}%`;
    scoreFill.className = `score-bar-fill sev-${severityClass(score)}`;
    scoreValue.textContent = String(score);
    scoreSev.textContent = severityClass(score);
    scoreSev.className = `sev-${severityClass(score)}`;
  }

  function scrubTo(percent) {
    if (!data) return;
    pause();
    baseOffset = (Math.max(0, Math.min(100, percent)) / 100) * totalMs;
    // Replay event log up to baseOffset from scratch (cheap — bounded set).
    renderHeader();
    lastEventIndex = -1;
    lastFrameIndex = -1;
    syncTimelineTo(baseOffset);
    elapsedEl.textContent = fmtMs(baseOffset);
    scrubber.value = String(percent);
  }

  playBtn.addEventListener('click', play);
  pauseBtn.addEventListener('click', pause);
  resetBtn.addEventListener('click', reset);
  scrubber.addEventListener('input', () => scrubTo(Number(scrubber.value)));
  speedSel.addEventListener('change', () => {
    if (playing) {
      // Recompute baseline so we stay at current virtual position.
      const now = currentVirtualMs();
      baseOffset = now;
      baseWall = performance.now();
    }
  });

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.HS || !window.HS.getToken()) return;
    if (!sessionId) {
      eventLog.innerHTML = '<p class="error">No session id in URL.</p>';
      return;
    }
    load();
  });
})();
