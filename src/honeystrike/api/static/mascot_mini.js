// Floating mini-mascot, XP badge, and first-visit "level briefing" overlay.
//
// Loaded on every non-lesson page from _base.html.  Provides a global
// `window.HSGame` API so other page scripts can bump XP / pop a hint /
// trigger the mascot to react.

(function () {
  const LS_XP        = 'hs_xp_v1';
  const LS_STREAK    = 'hs_streak_v1';
  const LS_COUNTS    = 'hs_counts_v1';
  const LS_ACTIVITY  = 'hs_activity_v1';
  const LS_BRIEF_PFX = 'hs_briefed_';      // + page key

  // ---- page registry ---------------------------------------------------
  // What page we're on is inferred from window.location.pathname so a
  // dropped-in script tag is enough.
  const PAGES = {
    dashboard: {
      match: (p) => p === '/' || p === '',
      title: '🗺  Live map briefing',
      tip:   "Each ping on the map is a real attack on your honeypots.  Click a marker to open the session.",
      briefing: `
        <p>This is the <strong>live attack map</strong>.  Every time a session closes
        with a threat score, you'll see it appear here within ~2 s.</p>
        <ul>
          <li>🟢 <strong>low</strong> &lt; 20  · 🟡 medium &lt; 50  · 🟠 high &lt; 80  · 🔴 critical</li>
          <li>Hover a marker for service + IP + score.</li>
          <li>The <em>Recent sessions</em> sidebar mirrors the same data; click any row to open the session.</li>
        </ul>
        <p class="muted">Tip: open <a href="/play/attack">🎮 Play → Attack</a> in another tab and fire a scenario — you'll watch your own attack land here.</p>`,
      tour: [
        { sel: '#overview', text: 'Stat tiles: last-24h sessions, unique IPs, average score, and critical count.' },
        { sel: '#map',      text: 'Geo-IP marker for every scored session.  Click for context.' },
        { sel: '.sidebar',  text: 'Most recent sessions.  Click a row to open the session detail.' },
      ],
    },
    sessions: {
      match: (p) => p === '/sessions',
      title: '📋  Sessions briefing',
      tip:   "Every captured attack lives here.  Filter by service or score.",
      briefing: `
        <p>Each row is one full TCP session.  We've already enriched it: geo-IP,
        ASN, AbuseIPDB score, tool fingerprint, MITRE TTPs, threat score.</p>
        <ul>
          <li>Click a row to open the session — events, payload preview, TTPs, alerts dispatched.</li>
          <li>Score colours match the live map.</li>
          <li>The 🎬 Replay button on each session shows the events fire in order, animated.</li>
        </ul>`,
      tour: [
        { sel: '.filters, form.filters, .filter-bar', text: 'Filter by service, severity, IP, time window.' },
        { sel: 'table',     text: 'Sortable table.  Each row is one session.' },
      ],
    },
    analytics: {
      match: (p) => p === '/analytics',
      title: '📊  Analytics briefing',
      tip:   "Charts of what attackers are doing.  Use them to spot trends.",
      briefing: `
        <p>Aggregated views across the last 7–30 days:</p>
        <ul>
          <li><strong>Top TTPs</strong> — which MITRE techniques are most active.  If T1110.001 dominates, you're being brute-forced.</li>
          <li><strong>Geo breakdown</strong> — where attackers connect from.</li>
          <li><strong>Timeline</strong> — sessions over time; spot bursts.</li>
        </ul>
        <p class="muted">Tip: a sudden spike in T1190 usually means someone scripted a CVE check — open <a href="/sessions?service=http">Sessions → http</a> to see the payloads.</p>`,
      tour: [],
    },
    warroom: {
      match: (p) => p === '/warroom',
      title: '📡  War room briefing',
      tip:   "Full-screen takeover for demos.  Wall-mount it.",
      briefing: `<p>Big stats, world map, scrolling ticker, top attackers + TTPs.  Best for a wall screen.  ESC the URL to leave.</p>`,
      tour: [],
    },
    play_attack: {
      match: (p) => p === '/play/attack',
      title: '🗡  Attack lessons',
      tip:   "Pick a lesson — type your way through it.  Mascot will keep you honest.",
      briefing: `<p>Each card is a typing lesson.  You'll learn one real attack by writing it.  Press Tab to autocomplete a line, Esc to reveal it.</p>`,
      tour: [],
    },
    play_defend: {
      match: (p) => p === '/play/defend',
      title: '🛡  Defender lessons',
      tip:   "Type detection rules.  We'll run them against a fixture and tell you if they catch the attack.",
      briefing: `<p>Each card is a TTP detection.  Type the rule body, then grade it against a fixture session.  The live <a href="/play/defend/arena">label-and-block arena</a> is still here too.</p>`,
      tour: [],
    },
    play: {
      match: (p) => p === '/play',
      title: '🎮  Welcome to Play',
      tip:   "Attack or Defend.  Pick a side.",
      briefing: `<p>Two paths.  <a href="/play/attack">🗡 Attack</a> teaches you to write attacks.  <a href="/play/defend">🛡 Defend</a> teaches you to detect them.  Same data, different chair.</p>`,
      tour: [],
    },
    profile: {
      match: (p) => p === '/profile',
      title: '👤  Your profile',
      tip:   "Rank, XP, badges, and what your honeypot has seen.",
      briefing: `<p>Your operator profile.  XP earned through lessons + correct labels + blocks gets you up the rank ladder.  Badges unlock as you hit specific milestones — completing every attack lesson, catching a canary, racking up a label streak, etc.</p>`,
      tour: [],
    },
    session_detail: {
      match: (p) => /^\/sessions\/[^/]+$/.test(p),
      title: '🔍  Session detail',
      tip:   "Everything we captured about one attack.  🎬 Replay it to see it unfold.",
      briefing: `<p>Source, tool fingerprint, MITRE TTPs, event preview, alerts.  The <em>Replay session</em> button animates the events in real time — great for explaining what happened to someone who wasn't watching.</p>`,
      tour: [],
    },
  };

  function currentPage() {
    const p = window.location.pathname;
    for (const [key, def] of Object.entries(PAGES)) {
      if (def.match(p)) return [key, def];
    }
    return ['unknown', null];
  }

  // ---- XP state --------------------------------------------------------
  function getXp()     { return Number(localStorage.getItem(LS_XP) || 0); }
  function getStreak() { return Number(localStorage.getItem(LS_STREAK) || 0); }

  function setXp(n) {
    localStorage.setItem(LS_XP, String(n));
    const el = document.getElementById('xp-value');
    if (el) el.textContent = String(n);
  }
  function setStreak(n) {
    localStorage.setItem(LS_STREAK, String(n));
    const el = document.getElementById('xp-streak-value');
    const wrap = document.getElementById('xp-streak');
    if (el) el.textContent = String(n);
    if (wrap) wrap.hidden = n <= 0;
  }

  function bumpXp(delta, reason) {
    const next = Math.max(0, getXp() + delta);
    setXp(next);
    const bubble = document.getElementById('xp-badge');
    if (bubble) {
      bubble.classList.remove('xp-flash');
      void bubble.offsetWidth;   // restart animation
      bubble.classList.add('xp-flash');
    }
    popMascot(delta > 0 ? 'cheer' : 'shock',
              delta > 0 ? `+${delta} XP — ${reason || 'nice'}` : `${delta} XP — ${reason || 'oops'}`);
  }
  function bumpStreak(delta) {
    const next = Math.max(0, getStreak() + delta);
    setStreak(next);
    if (delta > 0) {
      const c = readCounts();
      c.bestStreak = Math.max(c.bestStreak || 0, next);
      writeCounts(c);
    }
  }
  function resetStreak() { setStreak(0); }

  // ---- counters + activity log (for profile + badges) ------------------
  function readCounts() {
    try { return JSON.parse(localStorage.getItem(LS_COUNTS) || '{}'); }
    catch { return {}; }
  }
  function writeCounts(c) { localStorage.setItem(LS_COUNTS, JSON.stringify(c)); }
  function bumpCount(key, delta = 1) {
    const c = readCounts();
    c[key] = (c[key] || 0) + delta;
    writeCounts(c);
  }
  function addDoneLesson(family, id) {
    const c = readCounts();
    const set = new Set(c.lessonsDoneIds || []);
    set.add(`${family}:${id}`);
    c.lessonsDoneIds = [...set];
    c.lessonsDone = set.size;
    writeCounts(c);
  }
  function logActivity(icon, text) {
    let arr = [];
    try { arr = JSON.parse(localStorage.getItem(LS_ACTIVITY) || '[]'); } catch {}
    arr.unshift({ t: new Date().toISOString(), icon, text });
    arr = arr.slice(0, 50);
    localStorage.setItem(LS_ACTIVITY, JSON.stringify(arr));
  }

  // ---- mini-mascot reactions ------------------------------------------
  const beeBtn = document.getElementById('mascot-mini-bee');
  const bubble = document.getElementById('mascot-mini-bubble');
  const bubbleText = document.getElementById('mascot-mini-text');
  const dismissBtn = document.getElementById('mascot-mini-dismiss');

  let resetTimer = null;
  function setMiniState(state, ttl) {
    if (!beeBtn) return;
    beeBtn.classList.remove('idle', 'happy', 'shock', 'cheer', 'sleep');
    beeBtn.classList.add(state);
    clearTimeout(resetTimer);
    if (state !== 'idle' && state !== 'sleep') {
      resetTimer = setTimeout(() => {
        beeBtn.classList.remove(state);
        beeBtn.classList.add('idle');
      }, ttl || 1400);
    }
  }

  function popMascot(state, text, ttl) {
    if (!beeBtn) return;
    setMiniState(state, ttl);
    if (text && bubbleText && bubble) {
      bubbleText.textContent = text;
      bubble.hidden = false;
      clearTimeout(bubble._hide);
      bubble._hide = setTimeout(() => { bubble.hidden = true; }, ttl || 3500);
    }
  }

  // Toggle the speech bubble when user clicks the bee.
  if (beeBtn) {
    beeBtn.addEventListener('click', () => {
      const [, def] = currentPage();
      if (bubble.hidden) {
        bubbleText.textContent = def ? def.tip : "Hi — I'm the HoneyStrike tutor.";
        bubble.hidden = false;
      } else {
        bubble.hidden = true;
      }
    });
  }
  if (dismissBtn && bubble) {
    dismissBtn.addEventListener('click', (ev) => { ev.stopPropagation(); bubble.hidden = true; });
  }

  // ---- level-briefing overlay -----------------------------------------
  function showBriefing(def) {
    const overlay = document.getElementById('briefing-overlay');
    if (!overlay) return;
    document.getElementById('briefing-title').textContent = def.title;
    document.getElementById('briefing-body').innerHTML = def.briefing;
    overlay.hidden = false;
    const tourBtn = document.getElementById('briefing-tour-btn');
    const skipBtn = document.getElementById('briefing-skip-btn');
    tourBtn.hidden = !(def.tour && def.tour.length);
    function close() { overlay.hidden = true; }
    tourBtn.onclick = () => { close(); startTour(def.tour); };
    skipBtn.onclick = close;
    overlay.onclick = (e) => { if (e.target === overlay) close(); };
  }

  function markBriefed(pageKey) {
    localStorage.setItem(LS_BRIEF_PFX + pageKey, '1');
  }
  function wasBriefed(pageKey) {
    return localStorage.getItem(LS_BRIEF_PFX + pageKey) === '1';
  }

  // Simple element-highlight tour: walks `steps`, glow + tip per element.
  let tourTip = null;
  function startTour(steps) {
    if (!steps || !steps.length) return;
    let i = 0;
    function ensureTip() {
      if (tourTip) return tourTip;
      tourTip = document.createElement('div');
      tourTip.className = 'tour-tip';
      tourTip.innerHTML = `
        <span class="tour-tip-text"></span>
        <div class="tour-tip-actions">
          <button type="button" class="tour-next">Next ▸</button>
          <button type="button" class="tour-end muted">End</button>
        </div>`;
      document.body.appendChild(tourTip);
      tourTip.querySelector('.tour-next').addEventListener('click', () => step(i + 1));
      tourTip.querySelector('.tour-end').addEventListener('click', () => step(steps.length));
      return tourTip;
    }
    function clearGlow() {
      document.querySelectorAll('.tour-glow').forEach(e => e.classList.remove('tour-glow'));
    }
    function step(j) {
      clearGlow();
      i = j;
      if (i >= steps.length) {
        if (tourTip) { tourTip.remove(); tourTip = null; }
        popMascot('cheer', '🏁 Tour done — explore freely.');
        return;
      }
      const s = steps[i];
      const target = document.querySelector(s.sel);
      const tip = ensureTip();
      tip.querySelector('.tour-tip-text').textContent = s.text;
      if (target) {
        target.classList.add('tour-glow');
        const r = target.getBoundingClientRect();
        tip.style.top = (window.scrollY + r.bottom + 12) + 'px';
        tip.style.left = (window.scrollX + Math.max(12, r.left)) + 'px';
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      } else {
        tip.style.top = '120px';
        tip.style.left = '24px';
      }
    }
    step(0);
  }

  // ---- highlight active nav tab + dock button -------------------------
  function paintActiveNav() {
    const p = window.location.pathname;
    let key = 'dashboard';
    if (p === '/sessions' || p.startsWith('/sessions/')) key = 'sessions';
    else if (p === '/analytics') key = 'analytics';
    else if (p.startsWith('/play')) key = 'play';
    else if (p === '/warroom') key = 'warroom';
    else if (p === '/profile') key = 'profile';
    document.querySelectorAll(`nav a[data-nav="${key}"]`).forEach(el => el.classList.add('nav-active'));
    const dockBtn = document.querySelector(`.dock-btn[data-dock="${key}"]`);
    if (dockBtn) dockBtn.classList.add('active');
  }

  // ---- public API for other page scripts ------------------------------
  window.HSGame = {
    bumpXp,
    bumpStreak,
    resetStreak,
    react: popMascot,                 // (state, text, ttl?)
    flash: (text) => popMascot('happy', text),
    woops: (text) => popMascot('shock', text),
    onCanaryFound: () => {
      bumpXp(5, 'canary caught');
      bumpCount('canariesCaught');
      logActivity('🚩', 'Caught a canary in an attacker session.');
    },
    onLessonComplete: (family, id) => {
      bumpXp(15, 'lesson complete');
      if (family && id) addDoneLesson(family, id);
      else bumpCount('lessonsDone');
      logActivity('🎓', `Completed ${family || 'a'} lesson ${id ? '"' + id + '"' : ''}`.trim());
    },
    onCorrectLabel: () => {
      bumpXp(10, 'correct label'); bumpStreak(1);
      bumpCount('correctLabels');
      logActivity('✓', 'Correctly labelled / graded a TTP.');
    },
    onWrongLabel: () => {
      bumpXp(-2, 'wrong label'); resetStreak();
      bumpCount('wrongLabels');
      logActivity('✗', 'Wrong label — streak reset.');
    },
    onBlock: () => {
      bumpXp(3, 'attacker blocked');
      bumpCount('blocks');
      logActivity('🚫', 'Blocked an attacker IP.');
    },
  };

  document.addEventListener('DOMContentLoaded', () => {
    paintActiveNav();
    setXp(getXp());
    setStreak(getStreak());
    const [key, def] = currentPage();
    if (def) {
      // Idle tip text.
      if (bubbleText) bubbleText.textContent = def.tip;
      // First-visit briefing.
      if (!wasBriefed(key)) {
        setTimeout(() => { showBriefing(def); markBriefed(key); }, 400);
      }
    }
    // Sleepy after 60s of no input.
    let sleepTimer = setTimeout(() => setMiniState('sleep'), 60_000);
    ['keydown', 'mousemove', 'click', 'scroll'].forEach(ev => {
      window.addEventListener(ev, () => {
        clearTimeout(sleepTimer);
        if (beeBtn && beeBtn.classList.contains('sleep')) setMiniState('idle');
        sleepTimer = setTimeout(() => setMiniState('sleep'), 60_000);
      }, { passive: true });
    });
  });
})();
