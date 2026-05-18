// Shared auth helpers loaded on every authenticated page.
//
// We store the access token in sessionStorage. Refresh-on-expiry would be a
// nice Phase 5 addition; today an expired access token just bounces the user
// back to /login.

(function () {
  const TOKEN_KEY = 'hs_access_token';
  const LOGIN_PATH = '/login';

  function getToken() {
    return sessionStorage.getItem(TOKEN_KEY);
  }

  function clearToken() {
    sessionStorage.removeItem(TOKEN_KEY);
  }

  function redirectToLogin() {
    if (window.location.pathname !== LOGIN_PATH) {
      window.location.href = LOGIN_PATH;
    }
  }

  async function apiFetch(path, opts = {}) {
    const token = getToken();
    if (!token) {
      redirectToLogin();
      throw new Error('not authenticated');
    }
    const headers = Object.assign({}, opts.headers || {}, {
      'Authorization': `Bearer ${token}`,
    });
    const r = await fetch(path, { ...opts, headers, credentials: 'include' });
    if (r.status === 401) {
      clearToken();
      redirectToLogin();
      throw new Error('unauthorized');
    }
    return r;
  }

  async function logout() {
    try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }); } catch {}
    clearToken();
    redirectToLogin();
  }

  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('logout-btn');
    if (btn) btn.addEventListener('click', logout);
    if (!getToken() && window.location.pathname !== LOGIN_PATH) {
      redirectToLogin();
    }
  });

  // Expose the helpers as a tiny global namespace.
  window.HS = { getToken, apiFetch, logout };
})();
