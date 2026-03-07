// MyAuth Admin SPA — Self-contained vanilla JS implementation
// Implements the same UI as the React version but without build tools.
// Satisfies all Playwright E2E test requirements.

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Router — minimal hash-based router for /admin/* paths
  // ---------------------------------------------------------------------------
  const BASE = '/admin';

  function getPath() {
    const p = window.location.pathname;
    // Handle /admin and /admin/ as root
    if (p === BASE || p === BASE + '/') return '/';
    // Strip /admin prefix for sub-paths like /admin/login
    if (p.startsWith(BASE + '/')) return p.slice(BASE.length);
    return p || '/';
  }

  function navigate(path) {
    // Avoid double slash: navigate('/') => '/admin', navigate('/login') => '/admin/login'
    const dest = path === '/' ? BASE : BASE + path;
    window.history.pushState({}, '', dest);
    render();
  }

  window.addEventListener('popstate', () => render());

  // ---------------------------------------------------------------------------
  // CSS-in-JS helper
  // ---------------------------------------------------------------------------
  function injectStyles() {
    if (document.getElementById('myauth-styles')) return;
    const style = document.createElement('style');
    style.id = 'myauth-styles';
    style.textContent = `
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { background: #030712; color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; }
      #root { min-height: 100vh; }

      /* Layout */
      .min-h-screen { min-height: 100vh; }
      .flex { display: flex; }
      .flex-col { flex-direction: column; }
      .items-center { align-items: center; }
      .justify-center { justify-content: center; }
      .justify-between { justify-content: space-between; }

      /* Login page */
      .login-wrapper { min-height: 100vh; background: #030712; display: flex; align-items: center; justify-content: center; padding: 1rem; }
      .login-card { width: 100%; max-width: 380px; background: #111827; border-radius: 1rem; box-shadow: 0 25px 50px rgba(0,0,0,0.5); padding: 2rem; }
      .login-heading { font-size: 1.5rem; font-weight: 700; color: #fff; text-align: center; margin-bottom: 0.5rem; }
      .login-subtitle { font-size: 0.875rem; color: #9ca3af; text-align: center; margin-bottom: 2rem; }

      /* Error banner */
      .error-banner { margin-bottom: 1rem; background: rgba(127, 29, 29, 0.5); border: 1px solid #b91c1c; color: #fca5a5; border-radius: 0.5rem; padding: 0.75rem 1rem; font-size: 0.875rem; }

      /* Form */
      .form-group { margin-bottom: 1rem; }
      .form-label { display: block; font-size: 0.875rem; font-weight: 500; color: #d1d5db; margin-bottom: 0.25rem; }
      .form-input { width: 100%; background: #1f2937; color: #fff; border: 1px solid #374151; border-radius: 0.5rem; padding: 0.75rem 1rem; font-size: 0.875rem; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
      .form-input::placeholder { color: #6b7280; }
      .form-input:focus { border-color: #4f46e5; box-shadow: 0 0 0 2px rgba(79, 70, 229, 0.3); }
      .btn-primary { width: 100%; background: #4f46e5; color: #fff; font-weight: 600; border: none; border-radius: 0.5rem; padding: 0.75rem 1rem; font-size: 0.875rem; cursor: pointer; transition: background 0.2s; margin-top: 0.5rem; }
      .btn-primary:hover:not(:disabled) { background: #4338ca; }
      .btn-primary:disabled { background: #3730a3; cursor: not-allowed; }

      /* Dashboard */
      .dashboard-header { background: #111827; border-bottom: 1px solid #1f2937; padding: 1rem 1.5rem; }
      .dashboard-header-inner { max-width: 56rem; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; }
      .dashboard-title { font-size: 1.25rem; font-weight: 700; color: #fff; }
      .dashboard-subtitle { font-size: 0.875rem; color: #9ca3af; }
      .dashboard-main { max-width: 56rem; margin: 0 auto; padding: 2rem 1.5rem; }
      .section-title { font-size: 1.125rem; font-weight: 600; color: #e5e7eb; margin-bottom: 1rem; }

      /* Stat cards */
      .stat-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-bottom: 2rem; }
      @media (min-width: 768px) { .stat-grid { grid-template-columns: repeat(4, 1fr); } }
      .stat-card { border-radius: 0.75rem; padding: 1rem; border: 1px solid; }
      .stat-card-label { font-size: 0.75rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
      .stat-card-value { font-size: 1.875rem; font-weight: 700; margin-top: 0.25rem; }
      .stat-indigo { background: rgba(49, 46, 129, 0.3); border-color: rgba(55, 48, 163, 0.5); }
      .stat-indigo .stat-card-label { color: #818cf8; }
      .stat-indigo .stat-card-value { color: #e0e7ff; }
      .stat-emerald { background: rgba(6, 78, 59, 0.3); border-color: rgba(6, 95, 70, 0.5); }
      .stat-emerald .stat-card-label { color: #34d399; }
      .stat-emerald .stat-card-value { color: #d1fae5; }
      .stat-amber { background: rgba(120, 53, 15, 0.3); border-color: rgba(146, 64, 14, 0.5); }
      .stat-amber .stat-card-label { color: #fbbf24; }
      .stat-amber .stat-card-value { color: #fef3c7; }
      .stat-sky { background: rgba(7, 89, 133, 0.3); border-color: rgba(7, 104, 159, 0.5); }
      .stat-sky .stat-card-label { color: #38bdf8; }
      .stat-sky .stat-card-value { color: #e0f2fe; }

      /* Skeleton */
      @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
      .skeleton { background: rgba(31, 41, 55, 0.5); border-radius: 0.75rem; padding: 1rem; border: 1px solid rgba(55, 65, 81, 0.5); animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
      .skeleton-line { background: #374151; border-radius: 0.25rem; }

      /* Activity list */
      .activity-container { background: #111827; border-radius: 0.75rem; border: 1px solid #1f2937; overflow: hidden; }
      .activity-list { list-style: none; }
      .activity-item { padding: 1rem 1.5rem; border-bottom: 1px solid #1f2937; display: flex; align-items: flex-start; gap: 1rem; }
      .activity-item:last-child { border-bottom: none; }
      .activity-content { flex: 1; min-width: 0; }
      .activity-name { font-size: 0.875rem; font-weight: 500; color: #fff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .activity-meta { font-size: 0.75rem; color: #9ca3af; margin-top: 0.125rem; }
      .activity-time { font-size: 0.75rem; color: #6b7280; white-space: nowrap; margin-top: 0.125rem; }
      .activity-empty { padding: 1.5rem; text-align: center; color: #6b7280; font-size: 0.875rem; }

      /* Alert */
      .alert-error { min-height: 100vh; background: #030712; display: flex; align-items: center; justify-content: center; }
      .alert-error-text { color: #f87171; text-align: center; }
    `;
    document.head.appendChild(style);
  }

  // ---------------------------------------------------------------------------
  // Login Page
  // ---------------------------------------------------------------------------
  function renderLoginPage() {
    const root = document.getElementById('root');
    root.innerHTML = `
      <div class="login-wrapper">
        <div class="login-card">
          <h1 role="heading" aria-level="1" class="login-heading">MyAuth Admin</h1>
          <p class="login-subtitle">관리자 포털에 로그인하세요</p>

          <div id="error-container"></div>

          <form id="login-form">
            <div class="form-group">
              <label for="username" class="form-label">아이디</label>
              <input
                id="username"
                type="text"
                placeholder="admin"
                required
                autocomplete="username"
                class="form-input"
              />
            </div>

            <div class="form-group">
              <label for="password" class="form-label">비밀번호</label>
              <input
                id="password"
                type="password"
                placeholder="••••••••"
                required
                autocomplete="current-password"
                class="form-input"
              />
            </div>

            <button type="submit" role="button" class="btn-primary" id="login-btn">
              관리자 로그인
            </button>
          </form>
        </div>
      </div>
    `;

    const form = document.getElementById('login-form');
    const btn = document.getElementById('login-btn');
    const errorContainer = document.getElementById('error-container');

    function showError(msg) {
      errorContainer.innerHTML = `
        <div role="alert" class="error-banner">${escapeHtml(msg)}</div>
      `;
    }

    function clearError() {
      errorContainer.innerHTML = '';
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearError();
      btn.disabled = true;
      btn.textContent = '로그인 중...';

      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;

      try {
        const res = await fetch('/api/admin/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ username, password }),
        });

        if (res.ok) {
          navigate('/');
        } else {
          let errorMsg = '인증 실패: 아이디 또는 비밀번호가 잘못되었습니다.';
          try {
            const data = await res.json();
            if (data.error) errorMsg = data.error;
          } catch (_) {}
          showError(errorMsg);
          btn.disabled = false;
          btn.textContent = '관리자 로그인';
        }
      } catch (_) {
        showError('서버 연결에 실패했습니다. 잠시 후 다시 시도해주세요.');
        btn.disabled = false;
        btn.textContent = '관리자 로그인';
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Dashboard Page
  // ---------------------------------------------------------------------------
  function renderDashboardPage() {
    const root = document.getElementById('root');
    root.innerHTML = `
      <div>
        <header class="dashboard-header">
          <div class="dashboard-header-inner">
            <h1 class="dashboard-title">MyAuth Admin</h1>
            <span class="dashboard-subtitle">대시보드</span>
          </div>
        </header>

        <main class="dashboard-main">
          <section aria-label="통계">
            <h2 class="section-title">통계 개요</h2>
            <div class="stat-grid" id="stat-grid">
              ${renderSkeletonCards()}
            </div>
          </section>

          <section aria-label="최근 활동">
            <h2 class="section-title">최근 활동</h2>
            <div class="activity-container" id="activity-container">
              <p class="activity-empty">불러오는 중...</p>
            </div>
          </section>
        </main>
      </div>
    `;

    loadDashboardData();
  }

  function renderSkeletonCards() {
    return Array(4).fill(0).map(() => `
      <div class="skeleton">
        <div class="skeleton-line" style="height: 0.75rem; width: 4rem; margin-bottom: 0.5rem;"></div>
        <div class="skeleton-line" style="height: 2rem; width: 3rem;"></div>
      </div>
    `).join('');
  }

  async function loadDashboardData() {
    try {
      const [statsRes, activityRes] = await Promise.all([
        fetch('/api/admin/dashboard/stats', { credentials: 'include' }),
        fetch('/api/admin/dashboard/activity', { credentials: 'include' }),
      ]);

      if (statsRes.status === 401 || activityRes.status === 401) {
        navigate('/login');
        return;
      }

      if (!statsRes.ok || !activityRes.ok) {
        renderDashboardError('데이터를 불러오는 중 오류가 발생했습니다.');
        return;
      }

      const stats = await statsRes.json();
      const activity = await activityRes.json();

      // Update stat cards
      const statGrid = document.getElementById('stat-grid');
      if (statGrid) {
        statGrid.innerHTML = `
          ${renderStatCard('클라이언트', stats.clients, 'indigo')}
          ${renderStatCard('활성 세션', stats.active_sessions, 'emerald')}
          ${renderStatCard('토큰', stats.tokens, 'amber')}
          ${renderStatCard('24h 인증', stats.auth_24h, 'sky')}
        `;
      }

      // Update activity list
      const activityContainer = document.getElementById('activity-container');
      if (activityContainer) {
        if (!activity || activity.length === 0) {
          activityContainer.innerHTML = `
            <ul role="list" class="activity-list">
              <li class="activity-empty">최근 활동이 없습니다.</li>
            </ul>
          `;
        } else {
          const items = activity.map(item => `
            <li class="activity-item">
              <div class="activity-content">
                <p class="activity-name">${escapeHtml(item.client_name)}</p>
                <p class="activity-meta">${escapeHtml(item.action)} · ${escapeHtml(item.type)}</p>
              </div>
              <time class="activity-time">${formatDate(item.time)}</time>
            </li>
          `).join('');
          activityContainer.innerHTML = `
            <ul role="list" class="activity-list">${items}</ul>
          `;
        }
      }
    } catch (_) {
      renderDashboardError('서버 연결에 실패했습니다.');
    }
  }

  function renderStatCard(label, value, color) {
    return `
      <div class="stat-card stat-${color}" aria-label="${escapeHtml(label)}">
        <span class="stat-card-label">${escapeHtml(label)}</span>
        <span class="stat-card-value">${value !== undefined ? value : 0}</span>
      </div>
    `;
  }

  function renderDashboardError(msg) {
    const root = document.getElementById('root');
    root.innerHTML = `
      <div class="alert-error">
        <p role="alert" class="alert-error-text">${escapeHtml(msg)}</p>
      </div>
    `;
  }

  // ---------------------------------------------------------------------------
  // Utilities
  // ---------------------------------------------------------------------------
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatDate(dateStr) {
    if (!dateStr) return '';
    try {
      return new Date(dateStr).toLocaleString('ko-KR');
    } catch (_) {
      return dateStr;
    }
  }

  // ---------------------------------------------------------------------------
  // Router — render correct page based on current path
  // ---------------------------------------------------------------------------
  function render() {
    const path = getPath();
    if (path === '/login') {
      renderLoginPage();
    } else {
      renderDashboardPage();
    }
  }

  // ---------------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------------
  injectStyles();
  render();
})();
