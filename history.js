// History modal: recent checks + starred domains. Loaded on every page,
// alongside auth.js, but only ever opened via the nav "History" link that
// auth.js renders when someone is logged in. Relies on window.trueSealAuth
// (from auth.js) for the Supabase client and current user.

(function () {
  const MODAL_HTML = `
    <div class="auth-modal history-modal" role="dialog" aria-modal="true" aria-labelledby="history-modal-title">
      <button type="button" class="auth-modal-close" aria-label="Close">&times;</button>
      <h2 class="auth-form-title" id="history-modal-title">History</h2>

      <div class="history-tabs">
        <button type="button" class="history-tab active" data-tab="recent">Recent checks</button>
        <button type="button" class="history-tab" data-tab="starred">Starred domains</button>
      </div>

      <div class="history-tab-panel" id="history-panel-recent"></div>
      <div class="history-tab-panel" id="history-panel-starred" hidden></div>
    </div>
  `;

  let overlay = null;
  let modal = null;
  let lastFocused = null;

  function ensureModal() {
    if (overlay) return;

    overlay = document.createElement('div');
    overlay.className = 'auth-modal-overlay';
    overlay.id = 'history-modal-overlay';
    overlay.hidden = true;
    overlay.innerHTML = MODAL_HTML;
    document.body.appendChild(overlay);

    modal = overlay.querySelector('.auth-modal');
    const closeBtn = overlay.querySelector('.auth-modal-close');
    closeBtn.addEventListener('click', close);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) close();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !overlay.hidden) close();
    });

    overlay.querySelectorAll('.history-tab').forEach((tab) => {
      tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });
  }

  function switchTab(name) {
    overlay.querySelectorAll('.history-tab').forEach((t) => {
      t.classList.toggle('active', t.dataset.tab === name);
    });
    overlay.querySelector('#history-panel-recent').hidden = name !== 'recent';
    overlay.querySelector('#history-panel-starred').hidden = name !== 'starred';
  }

  function close() {
    overlay.hidden = true;
    document.body.style.overflow = '';
    if (lastFocused) lastFocused.focus();
  }

  function emptyState(text) {
    const p = document.createElement('p');
    p.className = 'history-empty';
    p.textContent = text;
    return p;
  }

  function scoreClass(score) {
    if (score >= 80) return 'score-good';
    if (score >= 50) return 'score-medium';
    return 'score-poor';
  }

  function relativeDate(iso) {
    const then = new Date(iso).getTime();
    const diffMin = Math.round((Date.now() - then) / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.round(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.round(diffHr / 24);
    if (diffDay < 30) return `${diffDay}d ago`;
    return new Date(iso).toLocaleDateString();
  }

  function triggerCheck(domain) {
    close();
    if (window.trueSealChecker && typeof window.trueSealChecker.runCheck === 'function') {
      window.trueSealChecker.runCheck(domain);
    } else {
      window.location.href = `index.html?domain=${encodeURIComponent(domain)}`;
    }
  }

  async function loadRecent(client, userId) {
    const panel = overlay.querySelector('#history-panel-recent');
    panel.replaceChildren(emptyState('Loading…'));

    const { data, error } = await client
      .from('check_history')
      .select('domain, score, checked_at')
      .eq('user_id', userId)
      .order('checked_at', { ascending: false })
      .limit(20);

    panel.replaceChildren();
    if (error || !data || data.length === 0) {
      panel.appendChild(emptyState('No checks yet. Run a check to see it here.'));
      return;
    }

    data.forEach((row) => {
      const el = document.createElement('div');
      el.className = 'history-row';

      const main = document.createElement('div');
      main.className = 'history-row-main';
      const domainEl = document.createElement('span');
      domainEl.className = 'history-domain';
      domainEl.textContent = row.domain;
      const metaEl = document.createElement('span');
      metaEl.className = 'history-meta';
      metaEl.textContent = relativeDate(row.checked_at);
      main.append(domainEl, metaEl);

      const scoreEl = document.createElement('span');
      scoreEl.className = `history-score ${scoreClass(row.score)}`;
      scoreEl.textContent = row.score;

      el.append(main, scoreEl);
      panel.appendChild(el);
    });
  }

  async function loadStarred(client, userId) {
    const panel = overlay.querySelector('#history-panel-starred');
    panel.replaceChildren(emptyState('Loading…'));

    const { data, error } = await client
      .from('starred_domains')
      .select('id, domain, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    panel.replaceChildren();
    if (error || !data || data.length === 0) {
      panel.appendChild(emptyState('No starred domains yet.'));
      return;
    }

    data.forEach((row) => {
      const el = document.createElement('div');
      el.className = 'history-row';

      const main = document.createElement('div');
      main.className = 'history-row-main history-row-clickable';
      main.tabIndex = 0;
      main.setAttribute('role', 'button');
      const domainEl = document.createElement('span');
      domainEl.className = 'history-domain';
      domainEl.textContent = row.domain;
      const metaEl = document.createElement('span');
      metaEl.className = 'history-meta';
      metaEl.textContent = 'Click to re-check';
      main.append(domainEl, metaEl);
      const trigger = () => triggerCheck(row.domain);
      main.addEventListener('click', trigger);
      main.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') trigger();
      });

      const unstarBtn = document.createElement('button');
      unstarBtn.type = 'button';
      unstarBtn.className = 'history-unstar';
      unstarBtn.setAttribute('aria-label', `Unstar ${row.domain}`);
      unstarBtn.textContent = '✕';
      unstarBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        unstarBtn.disabled = true;
        await client.from('starred_domains').delete().eq('id', row.id);
        el.remove();
        if (window.trueSealChecker) window.trueSealChecker.syncStarButton();
        if (!panel.querySelector('.history-row')) {
          panel.appendChild(emptyState('No starred domains yet.'));
        }
      });

      el.append(main, unstarBtn);
      panel.appendChild(el);
    });
  }

  async function open() {
    if (!window.trueSealAuth) return;
    lastFocused = document.activeElement;
    ensureModal();
    overlay.hidden = false;
    document.body.style.overflow = 'hidden';
    switchTab('recent');
    overlay.querySelector('.auth-modal-close').focus();

    await window.trueSealAuth.ready;
    const user = window.trueSealAuth.getUser();
    if (!user) {
      // Nav only shows the History link while logged in, but auth state
      // could theoretically flip between click and here — bail quietly.
      close();
      return;
    }

    const client = await window.trueSealAuth.getClient();
    loadRecent(client, user.id);
    loadStarred(client, user.id);
  }

  window.trueSealHistory = { open };
})();
