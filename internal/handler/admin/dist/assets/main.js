(function() {
  var loginPage = document.getElementById('page-login');
  var dashboardPage = document.getElementById('page-dashboard');
  var loginBtn = document.getElementById('login-btn');
  var loginId = document.getElementById('login-id');
  var loginPw = document.getElementById('login-pw');
  var loginError = document.getElementById('login-error');

  function getPath() {
    return window.location.pathname;
  }

  function navigate(path) {
    window.history.pushState(null, '', path);
    route();
  }

  function route() {
    var path = getPath();
    loginPage.style.display = 'none';
    dashboardPage.style.display = 'none';

    if (path === '/admin/login') {
      loginPage.style.display = 'block';
    } else if (path === '/admin' || path === '/admin/') {
      dashboardPage.style.display = 'block';
      loadStats();
    } else {
      // Default: show login
      loginPage.style.display = 'block';
    }
  }

  function loadStats() {
    fetch('/api/admin/stats', { credentials: 'same-origin' })
      .then(function(r) {
        if (r.status === 401) {
          navigate('/admin/login');
          return null;
        }
        return r.json();
      })
      .then(function(data) {
        if (!data) return;
        document.getElementById('stat-clients').textContent = data.clients;
        document.getElementById('stat-sessions').textContent = data.sessions;
        document.getElementById('stat-tokens').textContent = data.tokens;
        document.getElementById('stat-auth24h').textContent = data.auth_24h;
      })
      .catch(function() {
        // stats load failed - ignore
      });

    // Load recent activity placeholder
    var list = document.getElementById('activity-list');
    list.innerHTML = '<li>시스템 시작됨</li>';
  }

  loginBtn.addEventListener('click', function() {
    loginError.classList.remove('visible');
    var id = loginId.value;
    var pw = loginPw.value;

    fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ id: id, password: pw })
    })
    .then(function(r) {
      if (r.ok) {
        navigate('/admin');
      } else {
        loginError.classList.add('visible');
      }
    })
    .catch(function() {
      loginError.classList.add('visible');
    });
  });

  // Handle browser back/forward
  window.addEventListener('popstate', route);

  // Initial route
  route();
})();
