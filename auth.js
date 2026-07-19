// Shared auth behavior for every page (nav Log in/Sign up/Log out state +
// the modal). Loaded on index.html, what-we-do.html, glossary.html, and
// about.html, alongside the Supabase JS CDN script. The modal markup is
// built here rather than duplicated in four HTML files, so there's one
// place to change it.

(function () {
  const MODAL_HTML = `
    <div class="auth-modal" role="dialog" aria-modal="true" aria-labelledby="auth-modal-title-login">
      <button type="button" class="auth-modal-close" aria-label="Close">&times;</button>
      <p class="auth-modal-context" id="auth-modal-context" hidden></p>

      <form class="auth-form" id="auth-form-login" data-mode="login" novalidate>
        <h2 class="auth-form-title" id="auth-modal-title-login">Log in</h2>
        <p class="auth-form-error" id="auth-error-login" hidden></p>
        <label class="auth-field">
          <span>Email</span>
          <input type="email" id="login-email" required autocomplete="email">
        </label>
        <label class="auth-field">
          <span>Password</span>
          <input type="password" id="login-password" required autocomplete="current-password">
        </label>
        <button type="submit" class="auth-submit">Log in</button>
        <p class="auth-switch">Don't have an account? <a href="#" class="auth-switch-link" data-switch-to="signup">Sign up</a></p>
      </form>

      <form class="auth-form" id="auth-form-signup" data-mode="signup" novalidate hidden>
        <h2 class="auth-form-title" id="auth-modal-title-signup">Sign up</h2>
        <p class="auth-form-error" id="auth-error-signup" hidden></p>
        <label class="auth-field">
          <span>Email</span>
          <input type="email" id="signup-email" required autocomplete="email">
        </label>
        <label class="auth-field">
          <span>Password</span>
          <input type="password" id="signup-password" required autocomplete="new-password" minlength="6">
        </label>
        <button type="submit" class="auth-submit">Sign up</button>
        <p class="auth-switch">Already have an account? <a href="#" class="auth-switch-link" data-switch-to="login">Log in</a></p>
      </form>
    </div>
  `;

  const overlay = document.createElement('div');
  overlay.className = 'auth-modal-overlay';
  overlay.id = 'auth-modal-overlay';
  overlay.hidden = true;
  overlay.innerHTML = MODAL_HTML;
  document.body.appendChild(overlay);

  const modal = overlay.querySelector('.auth-modal');
  const closeBtn = overlay.querySelector('.auth-modal-close');
  const loginForm = document.getElementById('auth-form-login');
  const signupForm = document.getElementById('auth-form-signup');
  const loginError = document.getElementById('auth-error-login');
  const signupError = document.getElementById('auth-error-signup');
  const contextMessage = document.getElementById('auth-modal-context');
  const navAuth = document.querySelector('.site-nav-auth');

  let lastFocused = null;

  // contextMessage optionally replaces the generic modal with a reason it
  // was opened (e.g. "Log in to save starred domains"), for callers other
  // than the plain nav Log in/Sign up links.
  function openModal(mode, contextText) {
    lastFocused = document.activeElement;
    overlay.hidden = false;
    document.body.style.overflow = 'hidden';
    if (contextText) {
      contextMessage.textContent = contextText;
      contextMessage.hidden = false;
    } else {
      contextMessage.hidden = true;
      contextMessage.textContent = '';
    }
    showForm(mode);
  }

  function closeModal() {
    overlay.hidden = true;
    document.body.style.overflow = '';
    clearErrors();
    if (lastFocused) lastFocused.focus();
  }

  function showForm(mode) {
    clearErrors();
    const showSignup = mode === 'signup';
    signupForm.hidden = !showSignup;
    loginForm.hidden = showSignup;
    modal.setAttribute('aria-labelledby', showSignup ? 'auth-modal-title-signup' : 'auth-modal-title-login');
    const firstInput = (showSignup ? signupForm : loginForm).querySelector('input');
    if (firstInput) firstInput.focus();
  }

  function clearErrors() {
    loginError.hidden = true;
    loginError.textContent = '';
    signupError.hidden = true;
    signupError.textContent = '';
  }

  function showError(el, message) {
    el.textContent = message;
    el.hidden = false;
  }

  // Supabase's raw error messages are written for developers, not end
  // users — translate the common ones into the plain-language phrasing
  // the rest of the site uses; anything unrecognized falls back to the
  // message Supabase gave us rather than a generic "something went wrong",
  // since it's usually still readable.
  function friendlyAuthError(error) {
    const msg = (error && error.message) || '';
    if (/invalid login credentials/i.test(msg)) return 'Invalid email or password.';
    if (/already registered|user already registered/i.test(msg)) return 'An account with this email already exists.';
    if (/password.*(at least|should be|must be)/i.test(msg) && /6/.test(msg)) return 'Password must be at least 6 characters.';
    if (/unable to validate email|invalid email/i.test(msg)) return 'Please enter a valid email address.';
    return msg || 'Something went wrong. Please try again.';
  }

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !overlay.hidden) closeModal();
  });
  overlay.querySelectorAll('.auth-switch-link').forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      showForm(link.dataset.switchTo);
    });
  });

  let clientPromise = null;
  function getSupabaseClient() {
    if (!clientPromise) {
      clientPromise = fetch('/config')
        .then((r) => r.json())
        .then((config) => window.supabase.createClient(config.supabaseUrl, config.supabaseAnonKey));
    }
    return clientPromise;
  }

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearErrors();
    const submitBtn = loginForm.querySelector('.auth-submit');
    submitBtn.disabled = true;
    try {
      const client = await getSupabaseClient();
      const email = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;
      const { error } = await client.auth.signInWithPassword({ email, password });
      if (error) {
        showError(loginError, friendlyAuthError(error));
        return;
      }
      loginForm.reset();
      closeModal();
    } catch (err) {
      showError(loginError, "Couldn't connect. Check your connection and try again.");
    } finally {
      submitBtn.disabled = false;
    }
  });

  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearErrors();
    const submitBtn = signupForm.querySelector('.auth-submit');
    submitBtn.disabled = true;
    try {
      const client = await getSupabaseClient();
      const email = document.getElementById('signup-email').value.trim();
      const password = document.getElementById('signup-password').value;
      const { data, error } = await client.auth.signUp({ email, password });
      if (error) {
        showError(signupError, friendlyAuthError(error));
        return;
      }
      if (!data.session) {
        // Email confirmation is required on the Supabase project — no
        // session is issued until the user clicks the confirmation link.
        showError(signupError, 'Account created. Check your email to confirm it before logging in.');
        return;
      }
      signupForm.reset();
      closeModal();
    } catch (err) {
      showError(signupError, "Couldn't connect. Check your connection and try again.");
    } finally {
      submitBtn.disabled = false;
    }
  });

  function renderLoggedOut() {
    navAuth.replaceChildren();

    const loginLink = document.createElement('a');
    loginLink.href = '#';
    loginLink.className = 'nav-login';
    loginLink.textContent = 'Log in';
    loginLink.addEventListener('click', (e) => {
      e.preventDefault();
      openModal('login');
    });

    const signupLink = document.createElement('a');
    signupLink.href = '#';
    signupLink.className = 'nav-signup';
    signupLink.textContent = 'Sign up';
    signupLink.addEventListener('click', (e) => {
      e.preventDefault();
      openModal('signup');
    });

    navAuth.append(loginLink, signupLink);
  }

  function closeUserMenu() {
    const dropdown = navAuth.querySelector('.nav-user-dropdown');
    const avatarBtn = navAuth.querySelector('.nav-user-avatar');
    if (dropdown) dropdown.hidden = true;
    if (avatarBtn) avatarBtn.setAttribute('aria-expanded', 'false');
  }

  // Logged-in nav is a single avatar badge (first letter of the email) that
  // opens a dropdown with the full email, History, and Log out — replaces
  // three separate text items that used to crowd the nav, especially on
  // mobile where they collided with the logo.
  function renderLoggedIn(email) {
    navAuth.replaceChildren();

    const menu = document.createElement('div');
    menu.className = 'nav-user-menu';

    const avatarBtn = document.createElement('button');
    avatarBtn.type = 'button';
    avatarBtn.className = 'nav-user-avatar';
    avatarBtn.setAttribute('aria-haspopup', 'true');
    avatarBtn.setAttribute('aria-expanded', 'false');
    avatarBtn.setAttribute('aria-label', 'Account menu');
    avatarBtn.textContent = (email || '').trim().charAt(0).toUpperCase() || '?';

    const dropdown = document.createElement('div');
    dropdown.className = 'nav-user-dropdown';
    dropdown.hidden = true;

    const emailEl = document.createElement('p');
    emailEl.className = 'nav-user-dropdown-email';
    emailEl.textContent = email || '';

    const historyLink = document.createElement('a');
    historyLink.href = '#';
    historyLink.className = 'nav-history';
    historyLink.textContent = 'History';
    historyLink.addEventListener('click', (e) => {
      e.preventDefault();
      closeUserMenu();
      if (window.trueSealHistory) window.trueSealHistory.open();
    });

    const logoutLink = document.createElement('a');
    logoutLink.href = '#';
    logoutLink.className = 'nav-logout';
    logoutLink.textContent = 'Log out';
    logoutLink.addEventListener('click', async (e) => {
      e.preventDefault();
      closeUserMenu();
      const client = await getSupabaseClient();
      await client.auth.signOut();
    });

    dropdown.append(emailEl, historyLink, logoutLink);

    avatarBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.hidden = !dropdown.hidden;
      avatarBtn.setAttribute('aria-expanded', String(!dropdown.hidden));
    });

    menu.append(avatarBtn, dropdown);
    navAuth.append(menu);
  }

  document.addEventListener('click', (e) => {
    const dropdown = navAuth.querySelector('.nav-user-dropdown');
    if (!dropdown || dropdown.hidden) return;
    if (!dropdown.closest('.nav-user-menu').contains(e.target)) {
      closeUserMenu();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const dropdown = navAuth.querySelector('.nav-user-dropdown');
    if (dropdown && !dropdown.hidden) closeUserMenu();
  });

  // Paint the logged-out nav immediately (interactive right away, no flash
  // of dead links) while the session check happens in the background.
  renderLoggedOut();

  // currentUser + ready are exposed via window.trueSealAuth below so other
  // scripts (script.js's history-save/star logic, history.js's modal) can
  // read auth state without each re-fetching /config and creating their own
  // Supabase client.
  let currentUser = null;
  let resolveReady;
  const ready = new Promise((resolve) => {
    resolveReady = resolve;
  });

  (async () => {
    const client = await getSupabaseClient();
    // supabase-js fires this immediately with the current (possibly null)
    // session on subscribe, so this alone covers both the initial paint and
    // every later change — no separate getSession() call needed.
    client.auth.onAuthStateChange((_event, session) => {
      currentUser = session ? session.user : null;
      if (currentUser) {
        renderLoggedIn(currentUser.email);
      } else {
        renderLoggedOut();
      }
      resolveReady();
    });
  })();

  window.trueSealAuth = {
    getClient: getSupabaseClient,
    getUser: () => currentUser,
    openModal,
    ready
  };
})();
